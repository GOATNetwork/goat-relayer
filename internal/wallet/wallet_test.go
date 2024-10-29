package wallet

import (
	"testing"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestBTCClient(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("DB_DIR", tempDir)
	t.Setenv("L2_PRIVATE_KEY", "e9ccd0ec6bb77c263dc46c0f81962c0b378a67befe089e90ef81e96a4a4c5bc5")
	t.Setenv("BTC_RPC", "localhost:18332")
	t.Setenv("BTC_RPC_USER", "goat")
	t.Setenv("BTC_RPC_PASS", "goat")
	// Initialize config module
	config.InitConfig()

	// Modify connection configuration
	connConfig := &rpcclient.ConnConfig{
		Host:         config.AppConfig.BTCRPC,
		User:         config.AppConfig.BTCRPC_USER,
		Pass:         config.AppConfig.BTCRPC_PASS,
		HTTPPostMode: true,
		DisableTLS:   true,
	}

	// Create new RPC client
	btcClient, err := rpcclient.New(connConfig, nil)
	if err != nil {
		t.Fatalf("Failed to create Bitcoin client: %v", err)
	}
	defer btcClient.Shutdown()

	// Get block height
	height, err := btcClient.GetBlockCount()
	if err != nil {
		t.Errorf("Failed to get block height: %v", err)
	} else {
		t.Logf("Block height: %d", height)
		assert.Greater(t, height, int64(0), "Block height should be greater than 0")
	}

	// Get network information
	info, err := btcClient.GetNetworkInfo()
	if err != nil {
		t.Errorf("Failed to get network information: %v", err)
	} else {
		t.Logf("Network information: %+v", info)
		assert.NotNil(t, info, "Network information should not be nil")
	}

	// Print RPC configuration information for debugging
	t.Logf("BTC_RPC: %s", config.AppConfig.BTCRPC)
	t.Logf("BTC_USER: %s", config.AppConfig.BTCRPC_USER)
	t.Logf("BTC_PASS: %s", config.AppConfig.BTCRPC_PASS)
}
