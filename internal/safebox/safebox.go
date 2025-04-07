package safebox

import (
	"context"
	"fmt"
	"math/big"
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
		"status":    s.tssStatus,
		"sessionId": s.tssSession.SessionId,
		"taskId":    s.tssSession.TaskId,
		"expiredTs": s.tssSession.SignExpiredTs,
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
		TaskId:          task.TaskId,
		SessionId:       uuid.New().String(),
		SignExpiredTs:   time.Now().Unix() + 5*60,
		MessageToSign:   messageToSign,
		UnsignedTx:      unsignTx,
		Status:          db.TASK_STATUS_RECEIVED,
		Amount:          task.Amount,
		DepositAddress:  task.DepositAddress,
		FundingTxid:     task.FundingTxid,
		FundingOutIndex: task.FundingOutIndex,
	}

	s.logger.Infof("Set TSS session: SessionId=%s, TaskId=%d, ExpiresAt=%d",
		s.tssSession.SessionId, s.tssSession.TaskId, s.tssSession.SignExpiredTs)
}

func (s *SafeboxProcessor) buildUnsignedTx(ctx context.Context, task *db.SafeboxTask) (*ethtypes.Transaction, []byte, error) {
	safeBoxAbi, err := abis.TaskManagerContractMetaData.GetAbi()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get task contract ABI: %v", err)
	}
	to := common.HexToAddress(config.AppConfig.ContractTaskManager)
	s.logger.Infof("Building unsigned transaction - Contract address: %s", to.Hex())

	goatEthClient := s.layer2Listener.GetGoatEthClient()
	block, err := goatEthClient.BlockByNumber(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get block: %v", err)
	}
	baseFee := block.BaseFee()
	tip := big.NewInt(5000000) // current mainnet tip
	maxFeePerGas := new(big.Int).Add(baseFee, tip)
	s.logger.Infof("Gas settings - BaseFee: %v, Tip: %v, MaxFeePerGas: %v",
		baseFee, tip, maxFeePerGas)

	fromAddr := common.HexToAddress(s.tssAddress)
	s.logger.Infof("TSS address: %s", fromAddr.Hex())

	nonce, err := goatEthClient.PendingNonceAt(ctx, fromAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get pending nonce: %v", err)
	}
	s.logger.Infof("Current nonce: %d", nonce)

	// NOTE: UTXO amount decimal is 8, contract task amount decimal is 18
	amount := new(big.Int).Mul(big.NewInt(int64(task.Amount)), big.NewInt(1e10))
	s.logger.Infof("Converted amount: %v (from UTXO decimal 8 to contract decimal 18)", amount)

	// Convert slice to fixed length array
	txHashBytes := common.HexToHash(task.FundingTxid).Bytes()
	var fundingTxHash [32]byte
	copy(fundingTxHash[:], txHashBytes)
	s.logger.Infof("Funding transaction hash: %x", fundingTxHash)

	input, err := safeBoxAbi.Pack("receiveFunds", big.NewInt(int64(task.TaskId)), amount, fundingTxHash, uint32(task.FundingOutIndex))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to pack receiveFunds input: %v", err)
	}
	s.logger.Infof("Packed input data length: %d bytes", len(input))

	gasLimit := uint64(100000)
	s.logger.Infof("Using fixed gas limit: %d", gasLimit)

	// Call receiveFunds contract method
	s.logger.Infof("Creating unsigned transaction")
	unsignTx, messageToSign := tssCrypto.CreateEIP1559UnsignTx(
		big.NewInt(config.AppConfig.L2ChainId.Int64()),
		nonce,
		gasLimit,
		&to,
		maxFeePerGas,
		tip,
		new(big.Int).SetUint64(0), // value 0
		input)
	s.logger.Infof("Created unsigned transaction with chain ID: %d", config.AppConfig.L2ChainId.Int64())

	return unsignTx, messageToSign, nil
}

func (s *SafeboxProcessor) sendRawTx(ctx context.Context, tx *ethtypes.Transaction) error {
	s.logger.Infof("SafeboxProcessor sendRawTx - Sending transaction: Hash=%x, Nonce=%d, To=%s",
		tx.Hash(), tx.Nonce(), tx.To().Hex())

	goatEthClient := s.layer2Listener.GetGoatEthClient()
	err := goatEthClient.SendTransaction(ctx, tx)
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
			signedTx, err := s.tssSigner.ApplySignResult(ctx, s.tssSession.UnsignedTx, resp.Signature)
			if err != nil {
				s.logger.Errorf("SafeboxProcessor process - Failed to apply TSS sign result: %v, SessionId: %s", err, s.tssSession.SessionId)
				return
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
		s.resetTssAndSession(ctx)
		s.logger.Infof("SafeboxProcessor process - No signature received yet, SessionId: %s", s.tssSession.SessionId)
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
		s.logger.Debug("SafeboxProcessor process - No safebox tasks found")
		return
	}
	task := tasks[0]
	s.logger.Infof("SafeboxProcessor process - Processing task: TaskId=%d, Amount=%d, FundingTxid=%s, FundingOutIndex=%d",
		task.TaskId, task.Amount, task.FundingTxid, task.FundingOutIndex)

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
	p2p.PublishMessage(ctx, p2p.Message[any]{
		MessageType: p2p.MessageTypeSafeboxTask,
		RequestId:   fmt.Sprintf("SAFEBOX:%d:%s", task.TaskId, s.tssSession.SessionId),
		DataType:    "MsgSafeboxTask",
		Data:        s.tssSession,
	})
	s.logger.Infof("SafeboxProcessor process - Broadcasted safebox task: RequestId=SAFEBOX:%d:%s",
		task.TaskId, s.tssSession.SessionId)

	// start tss sign session immediately
	s.logger.Infof("SafeboxProcessor process - Starting TSS signing session")
	_, err = s.tssSigner.StartSign(ctx, messageToSign, s.tssSession.SessionId)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor process - Failed to start TSS sign: %v", err)
		return
	}
	s.logger.Infof("SafeboxProcessor process - Successfully started TSS signing session: SessionId=%s", s.tssSession.SessionId)
}
