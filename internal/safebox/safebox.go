package safebox

import (
	"context"
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
	"github.com/google/uuid"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	evmTypes "github.com/ethereum/go-ethereum/core/types"
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

// ?? perhaps better to move to p2p module
type TssSession struct {
	taskId uint64 // task id from db

	sessionId     string
	signExpiredTs int64 // tss sign expired ts
	messageToSign []byte
	unsignedTx    *evmTypes.Transaction

	signedTx *evmTypes.Transaction
}

type SafeboxProcessor struct {
	state          *state.State
	libp2p         *p2p.LibP2PService
	layer2Listener *layer2.Layer2Listener
	signer         *bls.Signer
	once           sync.Once

	db     *db.DatabaseManager
	logger *log.Entry

	tssSigner  *tss.Signer
	tssMu      sync.Mutex
	tssStatus  bool
	tssSession *TssSession
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
	}
}

func (s *SafeboxProcessor) Start(ctx context.Context) {

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

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.process(ctx)
		}
	}
}

func (s *SafeboxProcessor) resetTssAndSession(ctx context.Context) {
	s.tssMu.Lock()
	s.tssStatus = false
	s.tssSession = nil
	s.tssMu.Unlock()
}

func (s *SafeboxProcessor) process(ctx context.Context) {
	// TODO: check self is proposer first, if not, return
	if s.tssStatus {
		if s.tssSession.signedTx != nil {
			// TODO: signed tx found, check pending tx status, if tx cannot be found on chain, reset tss and session
			return
		}

		if s.tssSession.signExpiredTs > time.Now().Unix() {
			s.resetTssAndSession(ctx)
			return
		}

		// in sign window, query tss sign status
		resp, err := s.tssSigner.QuerySignResult(ctx, s.tssSession.sessionId)
		if err != nil {
			s.logger.Errorf("failed to query tss sign status: %v", err)
			return
		}
		if resp.Signature != nil {
			signedTx, err := s.tssSigner.ApplySignResult(ctx, s.tssSession.unsignedTx, resp.Signature)
			if err != nil {
				s.logger.Errorf("failed to apply tss sign result: %v", err)
				return
			}

			s.tssSession.signedTx = signedTx

			// TODO: Submit signed tx to layer2
			return
		}

		return
	}

	// TODO: query task from db (first one ID asc, until confirmed), build unsigned tx
	// TODO: broadcast unsigned tx to voters with "session_id", "expired_ts"
	// TODO: start tss sign session immediately

	// DEMO, should be changed to real task
	task := &db.SafeboxTask{
		ID: 1,
	}

	safeBoxAbi, err := abis.TaskManagerContractMetaData.GetAbi()
	if err != nil {
		log.Errorf("SafeboxProcessor, task contract abi not found")
		return
	}
	to := abis.TaskManagerAddress

	goatEthClient := s.layer2Listener.GetGoatEthClient()
	block, err := goatEthClient.BlockByNumber(ctx, nil)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor, get goat eth client block error: %v", err)
		return
	}
	baseFee := block.BaseFee()
	tip := big.NewInt(5000000) // current mainnet tip
	maxFeePerGas := new(big.Int).Add(baseFee, tip)

	// TODO: should get from Config
	fromAddr := common.HexToAddress("0x0000000000000000000000000000000000000000")
	// fromAddr, err := session0.GetAddressWithKDD()
	// to :=
	nonce, err := goatEthClient.PendingNonceAt(ctx, fromAddr)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor, get pending nonce error: %v", err)
		return
	}

	input, err := safeBoxAbi.Pack("receiveFunds",
		big.NewInt(int64(task.TaskId)),     // taskId
		big.NewInt(int64(task.Amount)),     // amount
		common.HexToHash(task.FundingTxid), // fundingTxHash
		uint32(task.FundingOutIndex),       // txOut
	)
	if err != nil {
		log.Errorf("SafeboxProcessor, receiveFunds input pack error: %v", err)
		return
	}

	gasLimit, err := goatEthClient.EstimateGas(ctx, ethereum.CallMsg{
		From:      fromAddr,
		To:        &to,
		Data:      input,
		Value:     big.NewInt(0),
		GasFeeCap: maxFeePerGas,
		GasTipCap: tip,
	})
	if err != nil {
		s.logger.Errorf("SafeboxProcessor, estimate gas error: %v", err)
		return
	}

	// Call receiveFunds contract method
	unsignTx, messageToSign := tssCrypto.CreateEIP1559UnsignTx(
		big.NewInt(config.AppConfig.L2ChainId.Int64()),
		nonce,
		gasLimit,
		&to,
		maxFeePerGas,
		tip,
		new(big.Int).SetUint64(0), // value 0
		input)

	s.tssMu.Lock()
	s.tssStatus = true
	s.tssSession = &TssSession{
		taskId:        task.TaskId,
		sessionId:     uuid.New().String(),
		signExpiredTs: time.Now().Unix() + 5*60,
		messageToSign: messageToSign,
		unsignedTx:    unsignTx,
	}
	s.tssMu.Unlock()

	_, err = s.tssSigner.StartSign(ctx, messageToSign, s.tssSession.sessionId)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor, start tss sign error: %v", err)
		return
	}
}
