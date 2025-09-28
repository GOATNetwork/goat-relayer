package config

import (
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

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
	viper.SetDefault("BTC_CONFIRMATIONS", 6)
	viper.SetDefault("BTC_START_HEIGHT", 0)
	viper.SetDefault("BTC_NETWORK_TYPE", "")
	viper.SetDefault("BTC_MAX_NETWORK_FEE", 500)
	viper.SetDefault("BTC_MAX_RANGE", 50)
	viper.SetDefault("BTC_REINDEX_BLOCKS", "")
	viper.SetDefault("BTC_AWS_SIGV4", false)
	viper.SetDefault("BTC_AWS_REGION", "us-east-1")
	viper.SetDefault("BTC_AWS_SERVICE", "managedblockchain")
	viper.SetDefault("CONTRACT_TASK_MANAGER", "0x6827D591faDa19A1274Df0Ab2608901AaaEA14C9")
	viper.SetDefault("L2_RPC", "http://localhost:8545")
	viper.SetDefault("L2_JWT_SECRET", "")
	viper.SetDefault("L2_CHAIN_ID", "2345")
	viper.SetDefault("L2_START_HEIGHT", 0)
	viper.SetDefault("L2_CONFIRMATIONS", 3)
	viper.SetDefault("L2_MAX_BLOCK_RANGE", 500)
	viper.SetDefault("L2_REQUEST_INTERVAL", "10s")
	viper.SetDefault("L2_SUBMIT_RETRY", 10)
	viper.SetDefault("TSS_ENDPOINT", "http://localhost:8080")
	viper.SetDefault("ENABLE_WEBHOOK", true)
	viper.SetDefault("ENABLE_RELAYER", true)
	viper.SetDefault("LOG_LEVEL", "info")
	viper.SetDefault("DB_DIR", "/app/db")
	viper.SetDefault("VOTING_CONTRACT", "")
	viper.SetDefault("WITHDRAW_CONTRACT", "")
	viper.SetDefault("FIREBLOCKS_SECRET", "")
	viper.SetDefault("FIREBLOCKS_CALLBACK_PRIVATE", "")
	viper.SetDefault("FIREBLOCKS_CALLBACK_PUBLIC", "")
	viper.SetDefault("FIREBLOCKS_API_KEY", "")
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
		BTCAWSSigV4:            viper.GetBool("BTC_AWS_SIGV4"),
		BTCAWSRegion:           viper.GetString("BTC_AWS_REGION"),
		BTCAWSService:          viper.GetString("BTC_AWS_SERVICE"),
		BTCStartHeight:         viper.GetInt("BTC_START_HEIGHT"),
		BTCReindexBlocks:       viper.GetString("BTC_REINDEX_BLOCKS"),
		BTCConfirmations:       viper.GetInt("BTC_CONFIRMATIONS"),
		BTCNetworkType:         viper.GetString("BTC_NETWORK_TYPE"),
		BTCMaxNetworkFee:       viper.GetInt("BTC_MAX_NETWORK_FEE"),
		BTCMaxRange:            viper.GetInt("BTC_MAX_RANGE"),
		ContractTaskManager:    viper.GetString("CONTRACT_TASK_MANAGER"),
		L2RPC:                  viper.GetString("L2_RPC"),
		L2JwtSecret:            viper.GetString("L2_JWT_SECRET"),
		L2ChainId:              big.NewInt(l2ChainId),
		L2StartHeight:          viper.GetInt("L2_START_HEIGHT"),
		L2Confirmations:        viper.GetInt("L2_CONFIRMATIONS"),
		L2MaxBlockRange:        viper.GetInt("L2_MAX_BLOCK_RANGE"),
		L2RequestInterval:      viper.GetDuration("L2_REQUEST_INTERVAL"),
		L2SubmitRetry:          viper.GetInt("L2_SUBMIT_RETRY"),
		TssEndpoint:            viper.GetString("TSS_ENDPOINT"),
		FireblocksSecret:       viper.GetString("FIREBLOCKS_SECRET"),
		FireblocksCallbackPriv: viper.GetString("FIREBLOCKS_CALLBACK_PRIVATE"),
		FireblocksCallbackPub:  viper.GetString("FIREBLOCKS_CALLBACK_PUBLIC"),
		FireblocksApiKey:       viper.GetString("FIREBLOCKS_API_KEY"),
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

	if (AppConfig.BTCNetworkType == "" || AppConfig.BTCNetworkType == "mainnet") && AppConfig.BTCConfirmations < 6 {
		logrus.Warnf("BTC mainnet confirmations is too low, set to 6")
		AppConfig.BTCConfirmations = 6
	}

	logrus.Infof("Init config, BlsSigTimeout %v, L2RequestInterval %v, RelayerAddress %s",
		AppConfig.BlsSigTimeout, AppConfig.L2RequestInterval, AppConfig.RelayerAddress)

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
	BTCAWSSigV4            bool
	BTCAWSRegion           string
	BTCAWSService          string
	BTCStartHeight         int
	BTCConfirmations       int
	BTCNetworkType         string
	BTCMaxNetworkFee       int
	BTCMaxRange            int
	BTCReindexBlocks       string
	ContractTaskManager    string
	L2RPC                  string
	L2JwtSecret            string
	L2ChainId              *big.Int
	L2StartHeight          int
	L2Confirmations        int
	L2MaxBlockRange        int
	L2RequestInterval      time.Duration
	L2SubmitRetry          int
	FireblocksSecret       string
	FireblocksCallbackPriv string
	FireblocksCallbackPub  string
	FireblocksApiKey       string
	TssEndpoint            string
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
