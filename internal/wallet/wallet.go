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
	libp2p *p2p.LibP2PService
	state  *state.State
	signer *bls.Signer
	once   sync.Once

	depositCh      chan interface{}
	blockCh        chan interface{}
	depositBatchCh chan DepositInfo
}

func NewWalletServer(libp2p *p2p.LibP2PService, st *state.State, signer *bls.Signer) *WalletServer {

	return &WalletServer{
		libp2p:         libp2p,
		state:          st,
		signer:         signer,
		depositCh:      make(chan interface{}, 100),
		blockCh:        make(chan interface{}, state.BTC_BLOCK_CHAN_LENGTH),
		depositBatchCh: make(chan DepositInfo, 100),
	}
}

func (w *WalletServer) Start(ctx context.Context) {
	w.state.EventBus.Subscribe(state.BlockScanned, w.blockCh)
	w.state.EventBus.Subscribe(state.DepositReceive, w.depositCh)

	go w.blockScanLoop(ctx)
	go w.depositLoop(ctx)
	go w.processConfirmedDeposit(ctx)
	go w.processBatchDeposit(w.depositBatchCh)

	log.Info("WalletServer started.")

	<-ctx.Done()
	w.Stop()

	log.Info("WalletServer stopped.")
}

func (w *WalletServer) Stop() {
	w.once.Do(func() {
		close(w.blockCh)
		close(w.depositCh)
	})
}
