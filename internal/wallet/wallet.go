package wallet

import (
	"context"
	"sync"

	"github.com/goatnetwork/goat-relayer/internal/bls"
	"github.com/goatnetwork/goat-relayer/internal/p2p"
	"github.com/goatnetwork/goat-relayer/internal/state"
	log "github.com/sirupsen/logrus"
)

type WalletServer struct {
	libp2p    *p2p.LibP2PService
	state     *state.State
	signer    *bls.Signer
	once      sync.Once
	sigMu     sync.Mutex
	sigStatus bool

	// after sig, it can start a new sig 2 blocks later
	sigFinishHeight uint64

	sigDepositMu           sync.Mutex
	sigDepositStatus       bool
	sigDepositFinishHeight uint64

	depositCh chan interface{}
	blockCh   chan interface{}

	depositSigFailChan    chan interface{}
	depositSigFinishChan  chan interface{}
	depositSigTimeoutChan chan interface{}

	withdrawSigFailChan    chan interface{}
	withdrawSigFinishChan  chan interface{}
	withdrawSigTimeoutChan chan interface{}
}

func NewWalletServer(libp2p *p2p.LibP2PService, st *state.State, signer *bls.Signer) *WalletServer {

	return &WalletServer{
		libp2p:    libp2p,
		state:     st,
		signer:    signer,
		depositCh: make(chan interface{}, 100),
		blockCh:   make(chan interface{}, state.BTC_BLOCK_CHAN_LENGTH),

		depositSigFailChan:    make(chan interface{}, 10),
		depositSigFinishChan:  make(chan interface{}, 10),
		depositSigTimeoutChan: make(chan interface{}, 10),

		withdrawSigFailChan:    make(chan interface{}, 10),
		withdrawSigFinishChan:  make(chan interface{}, 10),
		withdrawSigTimeoutChan: make(chan interface{}, 10),
	}
}

func (w *WalletServer) Start(ctx context.Context) {
	w.state.EventBus.Subscribe(state.BlockScanned, w.blockCh)
	w.state.EventBus.Subscribe(state.DepositReceive, w.depositCh)

	go w.blockScanLoop(ctx)
	go w.depositLoop(ctx)
	go w.withdrawLoop(ctx)

	log.Info("WalletServer started.")

	<-ctx.Done()
	w.Stop()

	log.Info("WalletServer stopped.")
}

func (w *WalletServer) Stop() {
	w.once.Do(func() {
		close(w.blockCh)
		close(w.depositCh)

		close(w.withdrawSigFailChan)
		close(w.withdrawSigFinishChan)
		close(w.withdrawSigTimeoutChan)
	})
}
