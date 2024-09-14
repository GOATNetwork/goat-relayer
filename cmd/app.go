package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/goatnetwork/goat-relayer/internal/bls"
	"github.com/goatnetwork/goat-relayer/internal/btc"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/http"
	"github.com/goatnetwork/goat-relayer/internal/layer2"
	"github.com/goatnetwork/goat-relayer/internal/p2p"
	"github.com/goatnetwork/goat-relayer/internal/rpc"
	"github.com/goatnetwork/goat-relayer/internal/state"
	log "github.com/sirupsen/logrus"
)

type Application struct {
	DatabaseManager *db.DatabaseManager
	State           *state.State
	Signer          *bls.Signer
	Layer2Listener  *layer2.Layer2Listener
	HTTPServer      *http.HTTPServer
	LibP2PService   *p2p.LibP2PService
	BTCListener     *btc.BTCListener
	UTXOService     *rpc.UtxoServer
}

func NewApplication() *Application {
	config.InitConfig()

	dbm := db.NewDatabaseManager()
	state := state.InitializeState(dbm)
	libP2PService := p2p.NewLibP2PService(state)
	layer2Listener := layer2.NewLayer2Listener(libP2PService, state, dbm)
	signer := bls.NewSigner(libP2PService, layer2Listener, state)
	httpServer := http.NewHTTPServer(libP2PService, state, dbm)
	btcListener := btc.NewBTCListener(libP2PService, state, dbm)
	utxoService := rpc.NewUtxoServer(state)

	return &Application{
		DatabaseManager: dbm,
		State:           state,
		Signer:          signer,
		Layer2Listener:  layer2Listener,
		LibP2PService:   libP2PService,
		HTTPServer:      httpServer,
		BTCListener:     btcListener,
		UTXOService:     utxoService,
	}
}

func (app *Application) Run() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		app.Layer2Listener.Start(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		app.LibP2PService.Start(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		app.Signer.Start(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		app.HTTPServer.Start(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		app.BTCListener.Start(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		app.UTXOService.Start(ctx)
	}()

	<-stop
	log.Info("Receiving exit signal...")

	cancel()

	wg.Wait()
	log.Info("Server stopped")
}
