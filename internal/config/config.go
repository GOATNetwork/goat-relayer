package config

import (
	"crypto/ecdsa"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/goatnetwork/goat-relayer/internal/types"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var AppConfig Config

func InitConfig() {
	viper.AutomaticEnv()

	// Default config
	viper.SetDefault("HTTP_PORT", "8080")
	viper.SetDefault("RPC_PORT", "50051")
	viper.SetDefault("LIBP2P_PORT", 4001)
	viper.SetDefault("LIBP2P_BOOT_NODES", "")
	viper.SetDefault("BTC_RPC", "http://localhost:8332")
	viper.SetDefault("BTC_RPC_USER", "")
	viper.SetDefault("BTC_RPC_PASS", "")
	viper.SetDefault("BTC_START_HEIGHT", 0)
	viper.SetDefault("L2_RPC", "http://localhost:8545")
	viper.SetDefault("L2_JWT_SECRET", "")
	viper.SetDefault("L2_PRIVATE_KEY", "")
	viper.SetDefault("L2_CHAIN_ID", "2345")
	viper.SetDefault("L2_START_HEIGHT", 0)
	viper.SetDefault("L2_CONFIRMATIONS", 3)
	viper.SetDefault("L2_MAX_BLOCK_RANGE", 500)
	viper.SetDefault("L2_REQUEST_INTERVAL", "10s")
	viper.SetDefault("L2_SUBMIT_RETRY", 10)
	viper.SetDefault("ENABLE_WEBHOOK", true)
	viper.SetDefault("ENABLE_RELAYER", true)
	viper.SetDefault("LOG_LEVEL", "info")
	viper.SetDefault("DB_DIR", "/app/db")
	viper.SetDefault("VOTING_CONTRACT", "")
	viper.SetDefault("WITHDRAW_CONTRACT", "")
	viper.SetDefault("FIREBLOCKS_PUBKEY", "")
	viper.SetDefault("FIREBLOCKS_PRIVKEY", "")
	viper.SetDefault("GOATCHAIN_RPC_URI", "tcp://127.0.0.1:26657")
	viper.SetDefault("GOATCHAIN_GRPC_URI", "127.0.0.1:9090")
	viper.SetDefault("GOATCHAIN_ID", "goat")
	viper.SetDefault("GOATCHAIN_ACCOUNT_PREFIX", "goat")
	viper.SetDefault("GOATCHAIN_DENOM", "ugoat")
	viper.SetDefault("RELAYER_PRIVATE_KEY", "")
	viper.SetDefault("RELAYER_BLS_SK", "")
	viper.SetDefault("BLS_SIG_TIMEOUT", "300s")

	logLevel, err := logrus.ParseLevel(strings.ToLower(viper.GetString("LOG_LEVEL")))
	if err != nil {
		logrus.Fatalf("Invalid log level: %v", err)
	}

	l2PrivateKey, err := crypto.HexToECDSA(viper.GetString("L2_PRIVATE_KEY"))
	if err != nil {
		logrus.Fatalf("Failed to load l2 private key: %v, given length %d", err, len(viper.GetString("L2_PRIVATE_KEY")))
	}

	l2ChainId, err := strconv.ParseInt(viper.GetString("L2_CHAIN_ID"), 10, 64)
	if err != nil {
		logrus.Fatalf("Failed to parse l2 chain id: %v", err)
	}

	relayerAddress, err := types.PrivateKeyToGoatAddress(viper.GetString("RELAYER_PRIVATE_KEY"), viper.GetString("GOATCHAIN_ACCOUNT_PREFIX"))
	if err != nil {
		log.Fatalf("Failed to parse goat address: %v, given private key length %d", err, len(viper.GetString("RELAYER_PRIVATE_KEY")))
	}

	AppConfig = Config{
		HTTPPort:               viper.GetString("HTTP_PORT"),
		RPCPort:                viper.GetString("RPC_PORT"),
		Libp2pPort:             viper.GetInt("LIBP2P_PORT"),
		Libp2pBootNodes:        viper.GetString("LIBP2P_BOOT_NODES"),
		BTCRPC:                 viper.GetString("BTC_RPC"),
		BTCRPC_USER:            viper.GetString("BTC_RPC_USER"),
		BTCRPC_PASS:            viper.GetString("BTC_RPC_PASS"),
		BTCStartHeight:         viper.GetInt("BTC_START_HEIGHT"),
		L2RPC:                  viper.GetString("L2_RPC"),
		L2JwtSecret:            viper.GetString("L2_JWT_SECRET"),
		L2PrivateKey:           l2PrivateKey,
		L2ChainId:              big.NewInt(l2ChainId),
		L2StartHeight:          viper.GetInt("L2_START_HEIGHT"),
		L2Confirmations:        viper.GetInt("L2_CONFIRMATIONS"),
		L2MaxBlockRange:        viper.GetInt("L2_MAX_BLOCK_RANGE"),
		L2RequestInterval:      viper.GetDuration("L2_REQUEST_INTERVAL"),
		L2SubmitRetry:          viper.GetInt("L2_SUBMIT_RETRY"),
		FireblocksPubKey:       viper.GetString("FIREBLOCKS_PUBKEY"),
		FireblocksPrivKey:      viper.GetString("FIREBLOCKS_PRIVKEY"),
		EnableWebhook:          viper.GetBool("ENABLE_WEBHOOK"),
		EnableRelayer:          viper.GetBool("ENABLE_RELAYER"),
		DbDir:                  viper.GetString("DB_DIR"),
		LogLevel:               logLevel,
		VotingContract:         viper.GetString("VOTING_CONTRACT"),
		WithdrawContract:       viper.GetString("WITHDRAW_CONTRACT"),
		GoatChainRPCURI:        viper.GetString("GOATCHAIN_RPC_URI"),
		GoatChainGRPCURI:       viper.GetString("GOATCHAIN_GRPC_URI"),
		GoatChainID:            viper.GetString("GOATCHAIN_ID"),
		GoatChainAccountPrefix: viper.GetString("GOATCHAIN_ACCOUNT_PREFIX"),
		GoatChainDenom:         viper.GetString("GOATCHAIN_DENOM"),
		RelayerPriKey:          viper.GetString("RELAYER_PRIVATE_KEY"),
		RelayerAddress:         relayerAddress,
		RelayerBlsSk:           viper.GetString("RELAYER_BLS_SK"),
		BlsSigTimeout:          viper.GetDuration("BLS_SIG_TIMEOUT"),
	}

	// logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(AppConfig.LogLevel)
}

type Config struct {
	HTTPPort               string
	RPCPort                string
	Libp2pPort             int
	Libp2pBootNodes        string
	BTCRPC                 string
	BTCRPC_USER            string
	BTCRPC_PASS            string
	BTCStartHeight         int
	L2RPC                  string
	L2JwtSecret            string
	L2PrivateKey           *ecdsa.PrivateKey
	L2ChainId              *big.Int
	L2StartHeight          int
	L2Confirmations        int
	L2MaxBlockRange        int
	L2RequestInterval      time.Duration
	L2SubmitRetry          int
	FireblocksPubKey       string
	FireblocksPrivKey      string
	EnableWebhook          bool
	EnableRelayer          bool
	DbDir                  string
	LogLevel               logrus.Level
	VotingContract         string
	WithdrawContract       string
	GoatChainRPCURI        string
	GoatChainGRPCURI       string
	GoatChainID            string
	GoatChainAccountPrefix string
	GoatChainDenom         string
	RelayerPriKey          string
	RelayerAddress         string
	RelayerBlsSk           string
	BlsSigTimeout          time.Duration
}
