package btc

import (
	"context"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/p2p"
	"github.com/goatnetwork/goat-relayer/internal/state"
	log "github.com/sirupsen/logrus"
)

type BTCListener struct {
	libp2p *p2p.LibP2PService
	dbm    *db.DatabaseManager
	state  *state.State

	notifier *BTCNotifier
}

func NewBTCListener(libp2p *p2p.LibP2PService, state *state.State, dbm *db.DatabaseManager) *BTCListener {
	db := dbm.GetBtcCacheDB()
	cache := NewBTCCache(db)
	poller := NewBTCPoller(state, db)

	connConfig := &rpcclient.ConnConfig{
		Host:         config.AppConfig.BTCRPC,
		User:         "test",
		Pass:         "test",
		HTTPPostMode: true,
		DisableTLS:   true,
	}
	client, err := rpcclient.New(connConfig, nil)
	if err != nil {
		log.Fatalf("failed to start bitcoin client: %v", err)
	}
	notifier := NewBTCNotifier(client, cache, poller)

	return &BTCListener{
		libp2p:   libp2p,
		dbm:      dbm,
		state:    state,
		notifier: notifier,
	}
}

func (bl *BTCListener) Start(ctx context.Context) {
	go bl.notifier.cache.Start(ctx)
	go bl.notifier.poller.Start(ctx)
	go bl.notifier.Start(ctx)

	log.Info("BTCListener started all modules")

	<-ctx.Done()
	log.Info("BTCListener is stopping...")
}
