package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/goatnetwork/goat-relayer/internal/awsutil"
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

	connConfig, err := BuildBTCConnConfig(config.AppConfig)
	if err != nil {
		log.Fatalf("Failed to build BTC RPC configuration: %v", err)
	}
	btcClient, err := rpcclient.New(connConfig, nil)
	if err != nil {
		log.Fatalf("Failed to start bitcoin client: %v", err)
	}

	if config.AppConfig.BTCAWSSigV4 {
		if err := awsutil.AttachSigV4Signer(
			btcClient,
			config.AppConfig.BTCAWSRegion,
			config.AppConfig.BTCAWSService,
			config.AppConfig.BTCRPC_USER,
			config.AppConfig.BTCRPC_PASS,
			os.Getenv("AWS_SESSION_TOKEN"),
		); err != nil {
			log.Fatalf("Failed to enable AWS SigV4 signing: %v", err)
		}

		if err := awsutil.PrimeBitcoindBackendVersion(btcClient); err != nil {
			log.Fatalf("Failed to detect bitcoind version: %v", err)
		}
	}

	dbm := db.NewDatabaseManager()
	state := state.InitializeState(dbm)
	libP2PService := p2p.NewLibP2PService(state)
	layer2Listener := layer2.NewLayer2Listener(libP2PService, state, dbm, btcClient)
	signer := bls.NewSigner(libP2PService, layer2Listener, state, btcClient)
	httpServer := http.NewHTTPServer(libP2PService, state, dbm)
	btcListener := btc.NewBTCListener(libP2PService, state, btcClient)
	utxoService := rpc.NewUtxoServer(state, layer2Listener, btcClient)
	btcRPCService := btc.NewBTCRPCService(btcClient)
	walletService := wallet.NewWalletServer(libP2PService, state, signer, btcClient, btcRPCService)
	voterProcessor := voter.NewVoterProcessor(libP2PService, state, signer)

	return &Application{
		DatabaseManager: dbm,
		State:           state,
		Signer:          signer,
		Layer2Listener:  layer2Listener,
		LibP2PService:   libP2PService,
		HTTPServer:      httpServer,
		BTCListener:     btcListener,
		UTXOService:     utxoService,
		WalletService:   walletService,
		VoterProcessor:  voterProcessor,
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
