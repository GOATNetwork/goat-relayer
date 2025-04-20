package safebox

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/layer2"
	"github.com/goatnetwork/goat-relayer/internal/layer2/abis"
	"github.com/goatnetwork/goat-relayer/internal/p2p"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/goatnetwork/goat-relayer/internal/tss"
	"github.com/goatnetwork/goat-relayer/internal/types"
	"github.com/google/uuid"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	tssCrypto "github.com/goatnetwork/tss/pkg/crypto"
	log "github.com/sirupsen/logrus"
)

/**
SafeboxProcessor is a processor that handles safebox tasks.
1. build unsigned transaction to tss signer, based on task record in db
2. proposer broadcast unsigned transaction to voters with "session_id", "expired_ts"
3. every voter(proposer included) sign the transaction via call tss signer
4. query tss sign status via "session_id", 5 minutes timeout
5. if signed, broadcast tx to voters, proposer send tx to layer2 (important: task status in db)
6. sender order flow should not be affected by safebox
7. if timeout, broadcast unsigned transaction again
8. !! important: only one tss session exists, need to manage tss address nonce self
*/

type SafeboxProcessor struct {
	state          *state.State
	libp2p         *p2p.LibP2PService
	layer2Listener *layer2.Layer2Listener
	once           sync.Once
	safeboxMu      sync.Mutex

	logger *log.Entry

	tssSigner  *tss.Signer
	tssMu      sync.RWMutex
	tssStatus  bool
	tssSession types.MsgSignInterface
	tssAddress string
	tssSignCh  chan interface{}
}

func NewSafeboxProcessor(state *state.State, libp2p *p2p.LibP2PService, layer2Listener *layer2.Layer2Listener) *SafeboxProcessor {
	return &SafeboxProcessor{
		state:          state,
		libp2p:         libp2p,
		layer2Listener: layer2Listener,

		logger: log.WithFields(log.Fields{
			"module": "safebox",
		}),

		tssSigner: tss.NewSigner(config.AppConfig.TssEndpoint, big.NewInt(config.AppConfig.L2ChainId.Int64())),
		tssSignCh: make(chan interface{}, 1000),
	}
}

func (s *SafeboxProcessor) Start(ctx context.Context) {
	tssAddress, err := s.tssSigner.GetTssAddress(ctx)
	if err != nil {
		s.logger.Fatalf("SafeboxProcessor, get tss address error: %v", err)
	}
	s.tssAddress = tssAddress
	s.logger.Infof("SafeboxProcessor - TSS ADDRESS: %s", s.tssAddress)

	// Check balance
	s.CheckTssBalance(ctx)

	go s.taskLoop(ctx)

	s.logger.Info("SafeboxProcessor started.")

	<-ctx.Done()
	s.Stop()

	s.logger.Info("SafeboxProcessor stopped.")
}

func (s *SafeboxProcessor) Stop() {
	s.once.Do(func() {
	})
}

func (s *SafeboxProcessor) taskLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	s.state.EventBus.Subscribe(state.SafeboxTask, s.tssSignCh)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.process(ctx)
		case msg := <-s.tssSignCh:
			tssSession := msg.(types.MsgSignSafeboxTask)
			s.handleTssSign(ctx, tssSession)
		}
	}
}

func (s *SafeboxProcessor) CheckTssStatus(ctx context.Context) error {
	if !s.tssStatus {
		return fmt.Errorf("TSS signing not started, should build an new session")
	}
	if s.tssSession == nil {
		return fmt.Errorf("TSS signing session is nil")
	}

	if s.tssSession.GetSignedTx() != nil {
		// TODO: signed tx found, check pending tx status, if tx cannot be found on chain, reset tss and session
		return fmt.Errorf("signed transaction already found, should reset tss and session")
	}
	if s.tssSession.CheckExpired() {
		s.ResetTssAndSession(ctx)
		return fmt.Errorf("TSS signing session expired, should reset tss and session")
	}
	return nil
}

func (s *SafeboxProcessor) ResetTssAndSession(ctx context.Context) {
	s.tssMu.Lock()
	s.tssStatus = false
	s.tssSession = nil
	s.tssMu.Unlock()
}

func (s *SafeboxProcessor) SetTssSession(requestId string, task *db.SafeboxTask, messageToSign []byte, unsignTx *ethtypes.Transaction) {
	s.tssMu.Lock()
	defer s.tssMu.Unlock()

	s.tssStatus = true
	taskBytes, err := json.Marshal(task)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor SetTssSession - Failed to marshal task: %v", err)
		return
	}
	s.tssSession = &types.MsgSignSafeboxTask{
		MsgSign: types.MsgSign{
			RequestId:  requestId,
			CreateTime: time.Now().Unix(),
			SigData:    messageToSign,
			UnsignedTx: unsignTx,
		},
		SafeboxTask: taskBytes,
	}

	s.logger.Infof("Set TSS session: RequestId=%s, TaskId=%d",
		s.tssSession.GetRequestId(), task.TaskId)
}

func (s *SafeboxProcessor) BuildUnsignedTx(ctx context.Context, task *db.SafeboxTask) (*ethtypes.Transaction, []byte, error) {
	// Get contract abi
	safeBoxAbi, err := abis.TaskManagerContractMetaData.GetAbi()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get task contract ABI: %v", err)
	}

	// Get tss address and contract call address
	fromAddr := common.HexToAddress(s.tssAddress)
	toAddr := common.HexToAddress(config.AppConfig.ContractTaskManager)

	// Get base fee
	goatEthClient := s.layer2Listener.GetGoatEthClient()
	block, err := goatEthClient.BlockByNumber(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get block: %v", err)
	}
	baseFee := block.BaseFee()
	tip := big.NewInt(5000000) // current mainnet tip
	maxFeePerGas := new(big.Int).Add(baseFee, tip)
	s.logger.Debugf("SafeboxProcessor buildUnsignedTx - BaseFee: %v, Tip: %v, MaxFeePerGas: %v", baseFee, tip, maxFeePerGas)

	// Get current nonce
	nonce, err := goatEthClient.PendingNonceAt(ctx, fromAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get pending nonce: %v", err)
	}
	s.logger.Debugf("SafeboxProcessor buildUnsignedTx - Current nonce: %d", nonce)

	var input []byte
	switch task.Status {
	case db.TASK_STATUS_RECEIVED:
		// NOTE: UTXO amount decimal is 8, contract task amount decimal is 18
		amount := new(big.Int).Mul(big.NewInt(int64(task.Amount)), big.NewInt(1e10))

		// Fullfill input data
		// Convert slice to fixed length array
		var fundingTxHash [32]byte
		txHashBytes, err := types.DecodeBtcHash(task.FundingTxid)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode funding transaction hash: %v", err)
		}
		copy(fundingTxHash[:], txHashBytes)
		s.logger.Debugf("SafeboxProcessor buildUnsignedTx - Packed input data: task id: %d, amount: %d, fundingTxHash: %s, fundingOutIndex: %d", task.TaskId, task.Amount, task.FundingTxid, task.FundingOutIndex)
		input, err = safeBoxAbi.Pack("receiveFunds", big.NewInt(int64(task.TaskId)), amount, fundingTxHash, uint32(task.FundingOutIndex))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to pack receiveFunds input: %v", err)
		}
	case db.TASK_STATUS_INIT, db.TASK_STATUS_RECEIVED_OK:
		// Fullfill input data
		// Convert slice to fixed length array
		var timelockTxHash [32]byte
		var witnessScript [7][32]byte
		txHashBytes, err := types.DecodeBtcHash(task.TimelockTxid)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode timelock transaction hash: %v", err)
		}
		copy(timelockTxHash[:], txHashBytes)

		// check witnessScript length
		totalBytes := len(task.WitnessScript)
		if totalBytes > 224 {
			return nil, nil, fmt.Errorf("witness script is too long, expected at most 224 bytes, got %d", totalBytes)
		}

		// safe copy witnessScript
		numArrays := (totalBytes + 31) / 32
		for i := 0; i < numArrays; i++ {
			start := i * 32
			end := start + 32
			if end > totalBytes {
				end = totalBytes
			}
			copy(witnessScript[i][:], task.WitnessScript[start:end])
		}

		s.logger.Debugf("SafeboxProcessor buildUnsignedTx - Packed input data: task id: %d, timelockTxHash: %s, timelockOutIndex: %d, witnessScript: %v", task.TaskId, task.TimelockTxid, task.TimelockOutIndex, witnessScript)
		input, err = safeBoxAbi.Pack("initTimelockTx", big.NewInt(int64(task.TaskId)), timelockTxHash, uint32(task.TimelockOutIndex), witnessScript)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to pack initTimelockTx input: %v", err)
		}
		s.logger.Debugf("SafeboxProcessor buildUnsignedTx - Packed input data length: %d bytes", len(input))
	case db.TASK_STATUS_CONFIRMED:
		input, err = safeBoxAbi.Pack("processTimelockTx", big.NewInt(int64(task.TaskId)), big.NewInt(int64(task.Amount)), [32]byte{}, uint32(task.FundingOutIndex))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to pack initTimelockTx input: %v", err)
		}
	default:
		return nil, nil, fmt.Errorf("invalid task status: %s", task.Status)
	}

	// Estimate gas limit
	gasLimit, err := goatEthClient.EstimateGas(ctx, ethereum.CallMsg{
		From:  fromAddr,
		To:    &toAddr,
		Value: new(big.Int).SetUint64(0), // set to 0, because funding amount is passed as a parameter
		Data:  input,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to estimate gas: %v", err)
	}

	// Call receiveFunds contract method
	unsignTx, messageToSign := tssCrypto.CreateEIP1559UnsignTx(
		big.NewInt(config.AppConfig.L2ChainId.Int64()),
		nonce,
		gasLimit,
		&toAddr,
		maxFeePerGas,
		tip,
		new(big.Int).SetUint64(0), // value 0
		input)
	s.logger.Infof("SafeboxProcessor buildUnsignedTx - Created unsigned transaction with chain ID: %d", config.AppConfig.L2ChainId.Int64())

	return unsignTx, messageToSign, nil
}

func (s *SafeboxProcessor) SendRawTx(ctx context.Context, tx *ethtypes.Transaction) error {
	s.logger.Infof("SafeboxProcessor sendRawTx - Sending transaction: Hash=%x, Nonce=%d, To=%s",
		tx.Hash(), tx.Nonce(), tx.To().Hex())

	// Show transaction chain ID and current configured chain ID
	txChainID := tx.ChainId()
	configChainID := big.NewInt(config.AppConfig.L2ChainId.Int64())
	s.logger.Debugf("SafeboxProcessor sendRawTx - TRANSACTION CHAIN ID: %v, CONFIG CHAIN ID: %v", txChainID, configChainID)
	if txChainID.Cmp(configChainID) != 0 {
		s.logger.Errorf("SafeboxProcessor sendRawTx - CHAIN ID MISMATCH! TX: %v, CONFIG: %v", txChainID, configChainID)
	}

	// Check TSS address balance
	fromAddr := common.HexToAddress(s.tssAddress)
	s.logger.Debugf("SafeboxProcessor sendRawTx - TRANSACTION FROM ADDRESS: %s", fromAddr.Hex())

	// Check if the transaction is correctly signed
	signer := ethtypes.LatestSignerForChainID(big.NewInt(config.AppConfig.L2ChainId.Int64()))
	sender, err := ethtypes.Sender(signer, tx)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor sendRawTx - TRANSACTION SENDER ERROR: %v", err)
	} else {
		s.logger.Debugf("SafeboxProcessor sendRawTx - RECOVERED TRANSACTION SENDER: %s", sender.Hex())
		if sender != fromAddr {
			s.logger.Errorf("SafeboxProcessor sendRawTx - SENDER ADDRESS MISMATCH! Expected: %s, Got: %s", fromAddr.Hex(), sender.Hex())
		}
	}

	// Check RPC connection information
	goatEthClient := s.layer2Listener.GetGoatEthClient()

	// Get current network ID
	networkID, err := goatEthClient.NetworkID(ctx)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor sendRawTx - FAILED TO GET NETWORK ID: %v", err)
	} else {
		s.logger.Debugf("SafeboxProcessor sendRawTx - CURRENT NETWORK ID: %v", networkID)
		if networkID.Cmp(configChainID) != 0 {
			s.logger.Errorf("SafeboxProcessor sendRawTx - NETWORK ID MISMATCH! NETWORK: %v, CONFIG: %v", networkID, configChainID)
		}
	}

	balance, err := goatEthClient.BalanceAt(ctx, fromAddr, nil)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor sendRawTx - Failed to get TSS address balance: %v", err)
		return fmt.Errorf("failed to get TSS address balance: %v", err)
	}

	// Record balance, including decimal representation
	ethBalance := new(big.Float).Quo(new(big.Float).SetInt(balance), new(big.Float).SetInt(big.NewInt(1e18)))
	s.logger.Debugf("SafeboxProcessor sendRawTx - FROM ADDRESS BALANCE: %s ETH (%s wei)",
		ethBalance.Text('f', 18), balance.String())

	// Check sender's balance again
	if sender != fromAddr {
		senderBalance, err := goatEthClient.BalanceAt(ctx, sender, nil)
		if err != nil {
			s.logger.Errorf("SafeboxProcessor sendRawTx - FAILED TO GET SENDER BALANCE: %v", err)
		} else {
			senderEthBalance := new(big.Float).Quo(new(big.Float).SetInt(senderBalance), new(big.Float).SetInt(big.NewInt(1e18)))
			s.logger.Debugf("SafeboxProcessor sendRawTx - SENDER ADDRESS BALANCE: %s ETH (%s wei)",
				senderEthBalance.Text('f', 18), senderBalance.String())
		}
	}

	// estimate gas price
	gasPrice, err := goatEthClient.SuggestGasPrice(ctx)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor sendRawTx - Failed to get gas price: %v", err)
		return fmt.Errorf("failed to get gas price: %v", err)
	}

	// estimate gas limit
	gasLimit, err := goatEthClient.EstimateGas(ctx, ethereum.CallMsg{
		From:  fromAddr,
		To:    tx.To(),
		Value: tx.Value(),
		Data:  tx.Data(),
	})
	if err != nil {
		s.logger.Errorf("SafeboxProcessor sendRawTx - Failed to estimate gas: %v", err)
		return fmt.Errorf("failed to estimate gas: %v", err)
	}

	// calculate tx cost
	txCost := new(big.Int).Mul(gasPrice, big.NewInt(int64(gasLimit)))
	s.logger.Infof("======== TRANSACTION COST: %s ETH ========",
		new(big.Float).Quo(new(big.Float).SetInt(txCost), new(big.Float).SetInt(big.NewInt(1e18))).Text('f', 18))

	// check balance is enough
	if balance.Cmp(txCost) < 0 {
		s.logger.Errorf("SafeboxProcessor sendRawTx - Insufficient balance: from address=%s, balance=%v, txCost=%v", fromAddr.Hex(), balance, txCost)
		return fmt.Errorf("insufficient balance: balance=%v, txCost=%v", balance, txCost)
	}

	err = goatEthClient.SendTransaction(ctx, tx)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor sendRawTx - Failed to send transaction: %v, Hash=%x", err, tx.Hash())
		return fmt.Errorf("failed to send transaction: %v", err)
	}

	s.logger.Infof("SafeboxProcessor sendRawTx - Successfully sent transaction: Hash=%x", tx.Hash())
	return nil
}

func (s *SafeboxProcessor) process(ctx context.Context) {
	s.logger.Debug("SafeboxProcessor process start")

	// check catching up
	l2Info := s.state.GetL2Info()
	if l2Info.Syncing {
		s.logger.Infof("SafeboxProcessor process ignored - Layer2 is catching up, Syncing: %v", l2Info.Syncing)
		return
	}

	btcState := s.state.GetBtcHead()
	if btcState.Syncing {
		s.logger.Infof("SafeboxProcessor process ignored - BTC is catching up, Syncing: %v", btcState.Syncing)
		return
	}

	s.safeboxMu.Lock()
	defer s.safeboxMu.Unlock()

	// check self is proposer first, if not, return
	epochVoter := s.state.GetEpochVoter()
	if epochVoter.Proposer != config.AppConfig.RelayerAddress {
		s.logger.Debugf("SafeboxProcessor process ignored - Not proposer, Epoch: %d, CurrentProposer: %s, SelfAddress: %s",
			epochVoter.Epoch, epochVoter.Proposer, config.AppConfig.RelayerAddress)
		return
	}
	s.logger.Infof("SafeboxProcessor process - Current proposer check passed, Epoch: %d", epochVoter.Epoch)

	// check if there is a tss sign in progress
	if err := s.CheckTssStatus(ctx); err == nil {
		// in sign window, query tss sign status
		if s.tssSession == nil {
			s.logger.Errorf("SafeboxProcessor process - No active TSS session")
			return
		}
		s.logger.Infof("SafeboxProcessor process - Querying TSS sign status, RequestId: %s", s.tssSession.GetRequestId())
		resp, err := s.tssSigner.QuerySignResult(ctx, s.tssSession.GetRequestId())
		if err != nil {
			s.logger.Errorf("SafeboxProcessor process - Failed to query TSS sign status: %v", err)
			return
		}
		if resp.Signature != nil {
			s.logger.Infof("SafeboxProcessor process - Signature received, applying to transaction, RequestId: %s", s.tssSession.GetRequestId())

			// Record signature information
			s.logger.Debugf("SafeboxProcessor process - SIGNATURE INFO")
			s.logger.Debugf("SafeboxProcessor process - SIGNATURE TYPE: %T", resp.Signature)
			s.logger.Debugf("SafeboxProcessor process - UNSIGNED TX TYPE: %T", s.tssSession.GetUnsignedTx())

			unsignedTx := s.tssSession.GetUnsignedTx()
			if unsignedTx == nil {
				s.logger.Errorf("SafeboxProcessor process - Unsigned transaction is nil")
				return
			}

			signedTx, err := s.tssSigner.ApplySignResult(ctx, unsignedTx, resp.Signature)
			if err != nil {
				s.logger.Errorf("SafeboxProcessor process - Failed to apply TSS sign result: %v, RequestId: %s", err, s.tssSession.GetRequestId())
				return
			}

			// Compare transaction information before and after signing
			s.logger.Debugf("SafeboxProcessor process - TX BEFORE/AFTER SIGNING")
			s.logger.Debugf("SafeboxProcessor process - UNSIGNED TX HASH: %s", s.tssSession.GetUnsignedTx().Hash().Hex())
			s.logger.Debugf("SafeboxProcessor process - SIGNED TX HASH: %s", signedTx.Hash().Hex())

			s.tssSession.SetSignedTx(signedTx)
			s.logger.Infof("SafeboxProcessor process - Successfully applied signature to transaction, RequestId: %s", s.tssSession.GetRequestId())

			// Submit signed tx to layer2
			err = s.SendRawTx(ctx, s.tssSession.GetSignedTx())
			if err != nil {
				s.logger.Errorf("SafeboxProcessor process - Failed to send signed transaction: %v, RequestId: %s", err, s.tssSession.GetRequestId())
				return
			}
			return
		}
		s.logger.Infof("SafeboxProcessor process - No signature received yet, RequestId: %s", s.tssSession.GetRequestId())
		s.ResetTssAndSession(ctx)
		return
	}

	// query task from db (first one ID asc, until confirmed), build unsigned tx
	s.logger.Infof("SafeboxProcessor process - Querying tasks from database")
	tasks, err := s.state.GetSafeboxTaskByStatus(1, db.TASK_STATUS_RECEIVED)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor process - Failed to get safebox tasks: %v", err)
		return
	}
	if len(tasks) == 0 {
		s.logger.Infof("SafeboxProcessor process - No safebox tasks found")
		return
	}
	task := tasks[0]

	unsignTx, messageToSign, err := s.BuildUnsignedTx(ctx, task)
	if err != nil {
		s.logger.Errorf("Failed to build unsigned transaction: %v", err)
		return
	}

	requestId := fmt.Sprintf("SAFEBOX:%d:%s", task.TaskId, uuid.New().String())
	s.SetTssSession(requestId, task, messageToSign, unsignTx)

	s.logger.Infof("SafeboxProcessor process - Created TSS session: RequestId=%s, TaskId=%d",
		s.tssSession.GetRequestId(), task.TaskId)

	// broadcast unsigned tx to voters with "session_id", "expired_ts"
	s.logger.Infof("SafeboxProcessor process - Broadcasting safebox task to voters")
	err = p2p.PublishMessage(ctx, p2p.Message[any]{
		MessageType: p2p.MessageTypeSafeboxTask,
		RequestId:   requestId,
		DataType:    "MsgSafeboxTask",
		Data:        s.tssSession,
	})
	if err != nil {
		s.logger.Errorf("SafeboxProcessor process - Failed to broadcast safebox task: %v", err)
		// broadcast failed, reset TSS status
		s.ResetTssAndSession(ctx)
		return
	}
	s.logger.Infof("SafeboxProcessor process - Broadcasted safebox task: RequestId=SAFEBOX:%d:%s",
		task.TaskId, s.tssSession.GetRequestId())

	// start tss sign session immediately
	s.logger.Infof("SafeboxProcessor process - Starting TSS signing session")
	_, err = s.tssSigner.StartSign(ctx, messageToSign, s.tssSession.GetRequestId())
	if err != nil {
		s.logger.Errorf("SafeboxProcessor process - Failed to start TSS sign: %v", err)
		// reset TSS status, because TSS signing session failed to start
		s.ResetTssAndSession(ctx)
		s.logger.Infof("SafeboxProcessor process - Reset TSS status due to failed StartSign call")
		return
	}
	s.logger.Infof("SafeboxProcessor process - Successfully started TSS signing session: RequestId=%s", s.tssSession.GetRequestId())
}

// check TSS address balance
func (s *SafeboxProcessor) CheckTssBalance(ctx context.Context) {
	goatEthClient := s.layer2Listener.GetGoatEthClient()
	balance, err := goatEthClient.BalanceAt(ctx, common.HexToAddress(s.tssAddress), nil)
	if err != nil {
		s.logger.Fatalf("SafeboxProcessor checkTssBalance - TSS ADDRESS BALANCE CHECK ERROR: %v", err)
		return
	}

	ethBalance := new(big.Float).Quo(new(big.Float).SetInt(balance), new(big.Float).SetInt(big.NewInt(1e18)))
	s.logger.Debugf("SafeboxProcessor checkTssBalance - TSS ADDRESS BALANCE: %s ETH", ethBalance.Text('f', 18))

	if balance.Cmp(big.NewInt(0)) == 0 {
		s.logger.Fatalf("SafeboxProcessor checkTssBalance - WARNING: TSS ADDRESS HAS ZERO BALANCE!")
		s.logger.Fatalf("SafeboxProcessor checkTssBalance - PLEASE SEND BALANCE TO: %s", s.tssAddress)
	}
}

func (s *SafeboxProcessor) GetTssSession() types.MsgSignInterface {
	return s.tssSession
}

func (s *SafeboxProcessor) GetTssSigner() *tss.Signer {
	return s.tssSigner
}
