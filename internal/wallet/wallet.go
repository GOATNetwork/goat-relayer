package wallet

import (
	"context"
	"sync"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/goatnetwork/goat-relayer/internal/bls"
	"github.com/goatnetwork/goat-relayer/internal/btc"
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

	rpcService *btc.BTCRPCService
}

func NewWalletServer(libp2p *p2p.LibP2PService, st *state.State, signer *bls.Signer, btcClient *rpcclient.Client, rpcService *btc.BTCRPCService) *WalletServer {
	return &WalletServer{
		libp2p:           libp2p,
		state:            st,
		signer:           signer,
		depositProcessor: NewDepositProcessor(btcClient, st, rpcService),
		orderBroadcaster: NewOrderBroadcaster(btcClient, st),
		blockCh:          make(chan interface{}, state.BTC_BLOCK_CHAN_LENGTH),

		lastProposerAddress: "",

		withdrawSigFailChan:    make(chan interface{}, 10),
		withdrawSigFinishChan:  make(chan interface{}, 10),
		withdrawSigTimeoutChan: make(chan interface{}, 10),
		rpcService:             rpcService,
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
		w.cleanWithdrawProcess()
		close(w.blockCh)
		close(w.withdrawSigFailChan)
		close(w.withdrawSigFinishChan)
		close(w.withdrawSigTimeoutChan)
	})
}
