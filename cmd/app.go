package main

import (
	"context"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/btcsuite/btcd/rpcclient"
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
	// Allow BTC_RPC to be either host:port or full URL so TLS can be inferred.
	rpcHost := config.AppConfig.BTCRPC
	disableTLS := true
	if parsed, err := url.Parse(rpcHost); err == nil && parsed.Host != "" {
		// Preserve path for APIs like GetBlock that use URL path for API key
		rpcHost = parsed.Host + parsed.Path
		disableTLS = parsed.Scheme != "https"
	}
	rpcHost = strings.TrimSuffix(rpcHost, "/")
	// Add default port if not specified
	if !strings.Contains(rpcHost, ":") {
		if disableTLS {
			rpcHost = rpcHost + ":80"
		} else {
			rpcHost = rpcHost + ":443"
		}
	}
	var extraHeaders map[string]string
	if config.AppConfig.BTCRPCApiKey != "" {
		extraHeaders = map[string]string{
			"x-api-key": config.AppConfig.BTCRPCApiKey,
		}
	}
	rpcUser := config.AppConfig.BTCRPC_USER
	rpcPass := config.AppConfig.BTCRPC_PASS
	// Default user/pass for APIs that don't require auth (e.g., GetBlock)
	if rpcUser == "" {
		rpcUser = "x"
	}
	if rpcPass == "" {
		rpcPass = "x"
	}
	// create bitcoin client using btc module connection
	connConfig := &rpcclient.ConnConfig{
		Host:         rpcHost,
		User:         rpcUser,
		Pass:         rpcPass,
		HTTPPostMode: true,
		DisableTLS:   disableTLS,
		ExtraHeaders: extraHeaders,
	}
	bclient, err := rpcclient.New(connConfig, nil)
	if err != nil {
		log.Fatalf("Failed to start bitcoin client: %v", err)
	}

	dbm := db.NewDatabaseManager()
	state := state.InitializeState(dbm)
	libP2PService := p2p.NewLibP2PService(state)
	btcClient := btc.NewBTCRPCService(bclient)

	// Test BTC RPC connection first
	log.Info("Testing BTC RPC connection...")
	blockCount, err := btcClient.GetBlockCount()
	if err != nil {
		log.Fatalf("Failed to get block count from BTC RPC: %v", err)
	}
	log.Infof("✅ BTC RPC connection successful! Current block count: %d", blockCount)

	layer2Listener := layer2.NewLayer2Listener(libP2PService, state, dbm, btcClient)
	httpServer := http.NewHTTPServer(libP2PService, state, dbm)
	btcListener := btc.NewBTCListener(libP2PService, state, btcClient)
	utxoService := rpc.NewUtxoServer(state, layer2Listener, btcClient)

	// Initialize BLS signer last (requires RELAYER_BLS_SK)
	signer := bls.NewSigner(libP2PService, layer2Listener, state, btcClient)
	walletService := wallet.NewWalletServer(libP2PService, state, signer, btcClient)
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
