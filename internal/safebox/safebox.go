package safebox

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/bls"
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
	"github.com/sirupsen/logrus"
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
	signer         *bls.Signer
	once           sync.Once
	safeboxMu      sync.Mutex

	db     *db.DatabaseManager
	logger *log.Entry

	tssSigner  *tss.Signer
	tssMu      sync.Mutex
	tssStatus  bool
	tssSession *types.TssSession
	tssAddress string
	tssSignCh  chan interface{}
}

func NewSafeboxProcessor(state *state.State, libp2p *p2p.LibP2PService, layer2Listener *layer2.Layer2Listener, signer *bls.Signer, db *db.DatabaseManager) *SafeboxProcessor {
	return &SafeboxProcessor{
		state:          state,
		libp2p:         libp2p,
		layer2Listener: layer2Listener,
		signer:         signer,
		db:             db,

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
	s.checkTssBalance(ctx)

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
			tssSession := msg.(types.TssSession)
			s.handleTssSign(ctx, tssSession)
		}
	}
}

func (s *SafeboxProcessor) checkTssStatus(ctx context.Context) bool {
	if !s.tssStatus {
		s.logger.Infof("SafeboxProcessor checkTssStatus - TSS signing not started, should build an new session, status: %v, sessionId: %v", s.tssStatus, s.tssSession)
		return false
	}
	if s.tssSession == nil {
		s.logger.Infof("SafeboxProcessor checkTssStatus - TSS signing session is nil, status: %v, sessionId: %v", s.tssStatus, s.tssSession)
		return false
	}
	s.logger.WithFields(log.Fields{
		"status":        s.tssStatus,
		"sessionId":     s.tssSession.SessionId,
		"taskId":        s.tssSession.TaskId,
		"expiredTs":     s.tssSession.SignExpiredTs,
		"messageToSign": fmt.Sprintf("%x", s.tssSession.MessageToSign),
	}).Info("TSS signing in progress")

	if s.tssSession.SignedTx != nil {
		s.logger.Infof("SafeboxProcessor checkTssStatus - Signed transaction already found, sessionId: %s", s.tssSession.SessionId)
		// TODO: signed tx found, check pending tx status, if tx cannot be found on chain, reset tss and session
		return false
	}
	if s.tssSession.SignExpiredTs < time.Now().Unix() {
		s.logger.Infof("SafeboxProcessor checkTssStatus - Resetting TSS and session due to expiration, sessionId: %s, expiredAt: %d",
			s.tssSession.SessionId, s.tssSession.SignExpiredTs)
		s.resetTssAndSession(ctx)
		return false
	}
	return true
}

func (s *SafeboxProcessor) resetTssAndSession(ctx context.Context) {
	s.tssMu.Lock()
	s.tssStatus = false
	s.tssSession = nil
	s.tssMu.Unlock()
}

func (s *SafeboxProcessor) setTssSession(task *db.SafeboxTask, messageToSign []byte, unsignTx *ethtypes.Transaction) {
	s.tssMu.Lock()
	defer s.tssMu.Unlock()

	s.tssStatus = true
	s.tssSession = &types.TssSession{
		TaskId:           task.TaskId,
		SessionId:        uuid.New().String(),
		SignExpiredTs:    time.Now().Unix() + 5*60,
		MessageToSign:    messageToSign,
		UnsignedTx:       unsignTx,
		Status:           task.Status,
		Amount:           task.Amount,
		TimelockEndTime:  task.TimelockEndTime,
		Pubkey:           task.Pubkey,
		DepositAddress:   task.DepositAddress,
		FundingTxid:      task.FundingTxid,
		FundingOutIndex:  task.FundingOutIndex,
		TimelockTxid:     task.TimelockTxid,
		TimelockOutIndex: task.TimelockOutIndex,
	}

	s.logger.Infof("Set TSS session: SessionId=%s, TaskId=%d, ExpiresAt=%d",
		s.tssSession.SessionId, s.tssSession.TaskId, s.tssSession.SignExpiredTs)
}

func (s *SafeboxProcessor) buildUnsignedTx(ctx context.Context, task *db.SafeboxTask) (*ethtypes.Transaction, []byte, error) {
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
		input, err = safeBoxAbi.Pack("receiveFunds", big.NewInt(int64(task.TaskId)), amount, fundingTxHash, uint32(task.FundingOutIndex))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to pack receiveFunds input: %v", err)
		}
		s.logger.Debugf("SafeboxProcessor buildUnsignedTx - Packed input data length: %d bytes", len(input))
	case db.TASK_STATUS_INIT:
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
		numArrays := (totalBytes + 31) / 32 // 向上取整
		for i := 0; i < numArrays; i++ {
			start := i * 32
			end := start + 32
			if end > totalBytes {
				end = totalBytes
			}
			copy(witnessScript[i][:], task.WitnessScript[start:end])
		}

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

func (s *SafeboxProcessor) sendRawTx(ctx context.Context, tx *ethtypes.Transaction) error {
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
	if s.checkTssStatus(ctx) {
		// in sign window, query tss sign status
		s.logger.Infof("SafeboxProcessor process - Querying TSS sign status, SessionId: %s", s.tssSession.SessionId)
		resp, err := s.tssSigner.QuerySignResult(ctx, s.tssSession.SessionId)
		if err != nil {
			s.logger.Errorf("SafeboxProcessor process - Failed to query TSS sign status: %v, SessionId: %s", err, s.tssSession.SessionId)
			return
		}
		if resp.Signature != nil {
			s.logger.Infof("SafeboxProcessor process - Signature received, applying to transaction, SessionId: %s", s.tssSession.SessionId)

			// Record signature information
			s.logger.Debugf("SafeboxProcessor process - SIGNATURE INFO")
			s.logger.Debugf("SafeboxProcessor process - SIGNATURE TYPE: %T", resp.Signature)
			s.logger.Debugf("SafeboxProcessor process - UNSIGNED TX TYPE: %T", s.tssSession.UnsignedTx)
			s.logger.Debugf("SafeboxProcessor process - UNSIGNED TX CHAIN ID: %v", s.tssSession.UnsignedTx.ChainId())

			signedTx, err := s.tssSigner.ApplySignResult(ctx, s.tssSession.UnsignedTx, resp.Signature)
			if err != nil {
				s.logger.Errorf("SafeboxProcessor process - Failed to apply TSS sign result: %v, SessionId: %s", err, s.tssSession.SessionId)
				return
			}

			// Compare transaction information before and after signing
			s.logger.Debugf("SafeboxProcessor process - TX BEFORE/AFTER SIGNING")
			s.logger.Debugf("SafeboxProcessor process - UNSIGNED TX HASH: %s", s.tssSession.UnsignedTx.Hash().Hex())
			s.logger.Debugf("SafeboxProcessor process - SIGNED TX HASH: %s", signedTx.Hash().Hex())

			signer := ethtypes.LatestSignerForChainID(signedTx.ChainId())
			sender, err := ethtypes.Sender(signer, signedTx)
			if err != nil {
				s.logger.Errorf("SafeboxProcessor process - FAILED TO RECOVER SENDER: %v", err)
			} else {
				s.logger.Debugf("SafeboxProcessor process - RECOVERED SENDER: %s", sender.Hex())
				s.logger.Debugf("SafeboxProcessor process - TSS ADDRESS: %s", s.tssAddress)
				if sender.Hex() != strings.ToLower(s.tssAddress) && sender.Hex() != strings.ToUpper(s.tssAddress) {
					s.logger.Errorf("SafeboxProcessor process - ADDRESSES DON'T MATCH!")
				}
			}

			s.tssSession.SignedTx = signedTx
			s.logger.Infof("SafeboxProcessor process - Successfully applied signature to transaction, SessionId: %s", s.tssSession.SessionId)

			// Submit signed tx to layer2
			err = s.sendRawTx(ctx, s.tssSession.SignedTx)
			if err != nil {
				s.logger.Errorf("SafeboxProcessor process - Failed to send signed transaction: %v, SessionId: %s", err, s.tssSession.SessionId)
				return
			}
			return
		}
		s.logger.Infof("SafeboxProcessor process - No signature received yet, SessionId: %s", s.tssSession.SessionId)
		s.resetTssAndSession(ctx)
		return
	}

	// query task from db (first one ID asc, until confirmed), build unsigned tx
	s.logger.Infof("SafeboxProcessor process - Querying tasks from database")
	tasks, err := s.state.GetSafeboxTaskByStatus(1, db.TASK_STATUS_RECEIVED, db.TASK_STATUS_INIT, db.TASK_STATUS_CONFIRMED)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor process - Failed to get safebox tasks: %v", err)
		return
	}
	if len(tasks) == 0 {
		s.logger.Infof("SafeboxProcessor process - No safebox tasks found")
		return
	}
	task := tasks[0]
	s.logger.WithFields(logrus.Fields{
		"task_id":            task.TaskId,
		"deposit_address":    task.DepositAddress,
		"amount":             task.Amount,
		"status":             task.Status,
		"funding_txid":       task.FundingTxid,
		"funding_out_index":  task.FundingOutIndex,
		"timelock_txid":      task.TimelockTxid,
		"timelock_out_index": task.TimelockOutIndex,
	}).Info("SafeboxProcessor process - Processing task")

	unsignTx, messageToSign, err := s.buildUnsignedTx(ctx, task)
	if err != nil {
		s.logger.Errorf("Failed to build unsigned transaction: %v", err)
		return
	}

	s.setTssSession(task, messageToSign, unsignTx)

	s.logger.Infof("SafeboxProcessor process - Created TSS session: SessionId=%s, TaskId=%d, ExpiresAt=%d",
		s.tssSession.SessionId, s.tssSession.TaskId, s.tssSession.SignExpiredTs)

	// broadcast unsigned tx to voters with "session_id", "expired_ts"
	s.logger.Infof("SafeboxProcessor process - Broadcasting safebox task to voters")
	err = p2p.PublishMessage(ctx, p2p.Message[any]{
		MessageType: p2p.MessageTypeSafeboxTask,
		RequestId:   fmt.Sprintf("SAFEBOX:%d:%s", task.TaskId, s.tssSession.SessionId),
		DataType:    "MsgSafeboxTask",
		Data:        s.tssSession,
	})
	if err != nil {
		s.logger.Errorf("SafeboxProcessor process - Failed to broadcast safebox task: %v", err)
		// broadcast failed, reset TSS status
		s.resetTssAndSession(ctx)
		return
	}
	s.logger.Infof("SafeboxProcessor process - Broadcasted safebox task: RequestId=SAFEBOX:%d:%s",
		task.TaskId, s.tssSession.SessionId)

	// start tss sign session immediately
	s.logger.Infof("SafeboxProcessor process - Starting TSS signing session")
	_, err = s.tssSigner.StartSign(ctx, messageToSign, s.tssSession.SessionId)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor process - Failed to start TSS sign: %v", err)
		// reset TSS status, because TSS signing session failed to start
		s.resetTssAndSession(ctx)
		s.logger.Infof("SafeboxProcessor process - Reset TSS status due to failed StartSign call")
		return
	}
	s.logger.Infof("SafeboxProcessor process - Successfully started TSS signing session: SessionId=%s", s.tssSession.SessionId)
}

// check TSS address balance
func (s *SafeboxProcessor) checkTssBalance(ctx context.Context) {
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
