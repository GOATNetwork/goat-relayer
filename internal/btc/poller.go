package btc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/goatnetwork/goat-relayer/internal/types"
	"gorm.io/gorm"

	log "github.com/sirupsen/logrus"
)

type SigHashQueue struct {
	Start  uint64
	Count  int
	Status bool
	Id     string
}

func NewSigHashQueue() *SigHashQueue {
	return &SigHashQueue{
		Start:  0,
		Count:  0,
		Status: false,
		Id:     "",
	}
}

type BTCPoller struct {
	db          *gorm.DB
	state       *state.State
	confirmChan chan *types.BtcBlockExt
	rpcService  *BTCRPCService

	lastStartHeight   uint64
	lastStartHeightMu sync.Mutex

	sigFailChan    chan interface{}
	sigFinishChan  chan interface{}
	sigTimeoutChan chan interface{}

	sigHashQueue *SigHashQueue
	sigHashMu    sync.Mutex
	once         sync.Once
}

func NewBTCPoller(state *state.State, rpcService *BTCRPCService) *BTCPoller {
	return &BTCPoller{
		state:       state,
		confirmChan: make(chan *types.BtcBlockExt, 64),
		rpcService:  rpcService,

		lastStartHeight: state.GetL2Info().StartBtcHeight,

		sigFailChan:    make(chan interface{}, 10),
		sigFinishChan:  make(chan interface{}, 10),
		sigTimeoutChan: make(chan interface{}, 10),

		sigHashQueue: NewSigHashQueue(),
	}
}

func (p *BTCPoller) Start(ctx context.Context) {
	go p.pollLoop(ctx)
	go p.signLoop(ctx)

	<-ctx.Done()
	log.Info("BTCPoller is stopping...")
	p.Stop()
}

func (p *BTCPoller) Stop() {
	p.once.Do(func() {
		close(p.sigFailChan)
		close(p.sigFinishChan)
		close(p.sigTimeoutChan)
		close(p.confirmChan)
	})
}

func (p *BTCPoller) pollLoop(ctx context.Context) {
	for {
		select {
		case block := <-p.confirmChan:
			p.handleConfirmedBlock(block)
		case <-ctx.Done():
			log.Info("Stopping the polling of confirmed blocks...")
			return
		}
	}
}

func (p *BTCPoller) signLoop(ctx context.Context) {
	p.state.EventBus.Subscribe(state.SigFailed, p.sigFailChan)
	p.state.EventBus.Subscribe(state.SigFinish, p.sigFinishChan)
	p.state.EventBus.Subscribe(state.SigTimeout, p.sigTimeoutChan)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case sigFail := <-p.sigFailChan:
			p.handleSigFailed(sigFail, "failed")
		case sigTimeout := <-p.sigTimeoutChan:
			p.handleSigFailed(sigTimeout, "timeout")
		case sigFinish := <-p.sigFinishChan:
			p.handleSigFinish(sigFinish)
		case <-ticker.C:
			p.initSig()
		}
	}
}

func (p *BTCPoller) handleConfirmedBlock(block *types.BtcBlockExt) {
	// Logic for handling confirmed blocks
	blockHash := block.BlockHash()
	log.Infof("Handling confirmed block: %d, hash:%s", block.BlockNumber, blockHash.String())

	if err := p.state.SaveConfirmBtcBlock(block.BlockNumber, blockHash.String()); err != nil {
		log.Fatalf("Save confirm btc block: %d, hash:%s, error: %v", block.BlockNumber, blockHash.String(), err)
	}

	// push to event bus
	p.state.EventBus.Publish(state.BlockScanned, *block)
}

func (p *BTCPoller) handleSigFailed(event interface{}, reason string) {
	p.sigHashMu.Lock()
	defer p.sigHashMu.Unlock()

	if !p.sigHashQueue.Status {
		log.Debugf("Event handleSigFailed with reason %s ignore, sigHashQueue status is false", reason)
		return
	}

	switch e := event.(type) {
	case types.MsgSignNewBlock:
		log.Infof("Event handleSigFailed is of type MsgSignNewBlock, request id %s, reason: %s", e.RequestId, reason)
		if e.RequestId == p.sigHashQueue.Id {
			p.sigHashQueue.Status = false
			// keep Start
		}
	default:
		log.Debug("BTCPoller signLoop ignore unsupport type")
	}
}

func (p *BTCPoller) handleSigFinish(event interface{}) {
	p.sigHashMu.Lock()
	defer p.sigHashMu.Unlock()

	if !p.sigHashQueue.Status {
		log.Debug("Event handleSigFinish ignore, sigHashQueue status is false")
		return
	}

	switch e := event.(type) {
	case types.MsgSignNewBlock:
		log.Infof("Event handleSigFinish is of type MsgSignNewBlock, request id %s", e.RequestId)
		if e.RequestId == p.sigHashQueue.Id {
			p.sigHashQueue.Status = false
			// update Start
			p.sigHashQueue.Start += uint64(p.sigHashQueue.Count)
		}
	default:
		log.Debug("BTCPoller signLoop ignore unsupport type")
	}
}

func (p *BTCPoller) initSig() {
	// 1. check catching up, self is proposer
	if p.state.GetL2Info().Syncing {
		log.Debug("BTCPoller initSig ignore, layer2 is catching up")
		return
	}

	p.sigHashMu.Lock()
	defer p.sigHashMu.Unlock()

	epochVoter := p.state.GetEpochVoter()
	if epochVoter.Proposer != config.AppConfig.RelayerAddress {
		p.sigHashQueue.Status = false
		log.Debugf("BTCPoller initSig ignore, self is not proposer, epoch: %d, proposer: %s", epochVoter.Epoch, epochVoter.Proposer)
		return
	}

	if p.sigHashQueue.Status {
		log.Debug("BTCPoller initSig ignore, there is a sig hash queue")
		return
	}

	// 2. get sig list, max 16 one time
	blocks, err := p.state.GetBtcBlockForSign(16)
	if err != nil {
		log.Errorf("BTCPoller initSig error: %v", err)
		return
	}
	if len(blocks) == 0 {
		log.Info("BTCPoller initSig pull btc block for sign return empty, ignore to sig")
		return
	}

	// 3. checking the height continuity, start <= [0].Height
	if p.sigHashQueue.Start > blocks[0].Height {
		// sig finish, wait layer2 detect btc block hash update
		log.Infof("BTCPoller initSig waiting for layer2 block hash update, sign hash queue start: %d, but get first block height: %d", p.sigHashQueue.Start, blocks[0].Height)
		return
	}

	if !p.isHeightContinuous(blocks) {
		log.Errorf("BTCPoller initSig pull btc block for sign not continuity, please check DB and btc client, start height: %d, result count: %d", blocks[0].Height, len(blocks))
		return
	}

	if blocks[0].Height < p.lastStartHeight {
		log.Debugf("BTCPoller initSig ignore, btc block height %d smaller than last sig queue start height %d", blocks[0].Height, p.lastStartHeight)
		return
	}
	p.lastStartHeightMu.Lock()
	p.lastStartHeight = blocks[0].Height
	p.lastStartHeightMu.Unlock()

	// 4. build sig msg
	requestId := fmt.Sprintf("BTCHEAD:%s:%d", config.AppConfig.RelayerAddress, blocks[0].Height)
	hashBytes := make([][]byte, len(blocks))
	for i, block := range blocks {
		hashBytes[i], err = types.DecodeBtcHash(block.Hash)
		if err != nil {
			log.Errorf("Decode btc block hash for sign, hash: %s, height: %d, error: %v", block.Hash, block.Height, err)
			return
		}
	}
	p.state.EventBus.Publish(state.SigStart, types.MsgSignNewBlock{
		MsgSign: types.MsgSign{
			RequestId:    requestId,
			Sequence:     epochVoter.Sequence,
			Epoch:        epochVoter.Epoch,
			IsProposer:   true,
			VoterAddress: epochVoter.Proposer,
			SigData:      nil,
			CreateTime:   time.Now().Unix(),
		},
		StartBlockNumber: blocks[0].Height,
		BlockHash:        hashBytes,
	})

	// 5. update status
	p.sigHashQueue.Status = true
	p.sigHashQueue.Id = requestId
	p.sigHashQueue.Count = len(blocks)
	// will update Start sig finish callback
	// p.sigHashQueue.Start = blocks[0].Height
}

func (p *BTCPoller) isHeightContinuous(blocks []*db.BtcBlock) bool {
	if len(blocks) <= 1 {
		return true
	}

	for i := 1; i < len(blocks); i++ {
		if blocks[i].Height != blocks[i-1].Height+1 {
			return false
		}
	}
	return true
}
