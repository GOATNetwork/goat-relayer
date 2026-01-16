package btc

import (
	"context"

	"github.com/goatnetwork/goat-relayer/internal/p2p"
	"github.com/goatnetwork/goat-relayer/internal/state"
	log "github.com/sirupsen/logrus"
)

type BTCListener struct {
	libp2p *p2p.LibP2PService
	state  *state.State

	notifier *BTCNotifier
}

func NewBTCListener(libp2p *p2p.LibP2PService, state *state.State, rpcService *BTCRPCService) *BTCListener {
	poller := NewBTCPoller(state, rpcService)
	notifier := NewBTCNotifier(rpcService, poller)

	return &BTCListener{
		libp2p:   libp2p,
		state:    state,
		notifier: notifier,
	}
}

func (bl *BTCListener) Start(ctx context.Context, blockDoneCh chan struct{}) {
	go bl.notifier.Start(ctx, blockDoneCh)
	log.Info("BTCListener started all modules")

	<-ctx.Done()
	log.Info("BTCListener is stopping...")
}
