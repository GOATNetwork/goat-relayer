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
	"github.com/goatnetwork/goat-relayer/internal/safebox"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/goatnetwork/goat-relayer/internal/voter"
	"github.com/goatnetwork/goat-relayer/internal/wallet"
	log "github.com/sirupsen/logrus"
)

type Application struct {
	DatabaseManager  *db.DatabaseManager
	State            *state.State
	Signer           *bls.Signer
	Layer2Listener   *layer2.Layer2Listener
	HTTPServer       *http.HTTPServer
	LibP2PService    *p2p.LibP2PService
	BTCListener      *btc.BTCListener
	UTXOService      *rpc.UtxoServer
	WalletService    *wallet.WalletServer
	VoterProcessor   *voter.VoterProcessor
	SafeboxProcessor *safebox.SafeboxProcessor
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
	utxoService := rpc.NewUtxoServer(state, layer2Listener)
	walletService := wallet.NewWalletServer(libP2PService, state, signer)
	voterProcessor := voter.NewVoterProcessor(libP2PService, state, signer)
	safeboxProcessor := safebox.NewSafeboxProcessor(state, libP2PService, layer2Listener, signer, dbm)

	return &Application{
		DatabaseManager:  dbm,
		State:            state,
		Signer:           signer,
		Layer2Listener:   layer2Listener,
		LibP2PService:    libP2PService,
		HTTPServer:       httpServer,
		BTCListener:      btcListener,
		UTXOService:      utxoService,
		WalletService:    walletService,
		VoterProcessor:   voterProcessor,
		SafeboxProcessor: safeboxProcessor,
	}
}

func (app *Application) Run() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	blockDoneCh := make(chan struct{})
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
		app.BTCListener.Start(ctx, blockDoneCh)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		app.UTXOService.Start(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		app.WalletService.Start(ctx, blockDoneCh)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		app.VoterProcessor.Start(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		app.SafeboxProcessor.Start(ctx)
	}()

	<-stop
	log.Info("Receiving exit signal...")
	close(blockDoneCh)

	cancel()

	wg.Wait()
	log.Info("Server stopped")
}

func main() {
	app := NewApplication()
	app.Run()
}
