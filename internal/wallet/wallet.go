package wallet

import (
	"context"
	"sync"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/goatnetwork/goat-relayer/internal/bls"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/p2p"
	"github.com/goatnetwork/goat-relayer/internal/state"
	log "github.com/sirupsen/logrus"
)

type WalletServer struct {
	libp2p *p2p.LibP2PService
	state  *state.State
	signer *bls.Signer
	once   sync.Once

	depositProcessor DepositProcessor
	orderBroadcaster OrderBroadcaster

	// after sig, it can start a new sig 2 blocks later
	sigMu                        sync.Mutex
	sigStatus                    bool
	lastProposerAddress          string
	sigFinishHeight              uint64
	finalizeWithdrawStatus       bool
	finalizeWithdrawFinishHeight uint64
	cancelWithdrawStatus         bool
	cancelWithdrawFinishHeight   uint64

	blockCh chan interface{}

	withdrawSigFailChan    chan interface{}
	withdrawSigFinishChan  chan interface{}
	withdrawSigTimeoutChan chan interface{}
}

func NewWalletServer(libp2p *p2p.LibP2PService, st *state.State, signer *bls.Signer) *WalletServer {
	// create bitcoin client using btc module connection
	connConfig := &rpcclient.ConnConfig{
		Host:         config.AppConfig.BTCRPC,
		User:         config.AppConfig.BTCRPC_USER,
		Pass:         config.AppConfig.BTCRPC_PASS,
		HTTPPostMode: true,
		DisableTLS:   true,
	}
	btcClient, err := rpcclient.New(connConfig, nil)
	if err != nil {
		log.Fatalf("Failed to start bitcoin client: %v", err)
	}

	return &WalletServer{
		libp2p:           libp2p,
		state:            st,
		signer:           signer,
		depositProcessor: NewDepositProcessor(btcClient, st),
		orderBroadcaster: NewOrderBroadcaster(btcClient, st),
		blockCh:          make(chan interface{}, state.BTC_BLOCK_CHAN_LENGTH),

		lastProposerAddress: "",

		withdrawSigFailChan:    make(chan interface{}, 10),
		withdrawSigFinishChan:  make(chan interface{}, 10),
		withdrawSigTimeoutChan: make(chan interface{}, 10),
	}
}

func (w *WalletServer) Start(ctx context.Context, blockDoneCh chan struct{}) {
	w.state.EventBus.Subscribe(state.BlockScanned, w.blockCh)

	go w.blockScanLoop(ctx, blockDoneCh)
	go w.withdrawLoop(ctx)

	go w.depositProcessor.Start(ctx)
	go w.orderBroadcaster.Start(ctx)

	log.Info("WalletServer started.")

	<-ctx.Done()
	w.Stop()

	log.Info("WalletServer stopped.")
}

func (w *WalletServer) Stop() {
	w.once.Do(func() {
		close(w.blockCh)

		close(w.withdrawSigFailChan)
		close(w.withdrawSigFinishChan)
		close(w.withdrawSigTimeoutChan)
	})
}
