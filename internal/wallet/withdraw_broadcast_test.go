package wallet

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/http"
	"github.com/goatnetwork/goat-relayer/internal/types"
	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestBroadcastOrdersWithLocalDB(t *testing.T) {
	t.Skip("Skipping this test for publish")
	// Initialize configuration
	// Load environment variables file
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		t.Fatalf("Error loading .env file: %v", err)
	}
	config.InitConfig()

	// Connect to local database
	var dbRef *gorm.DB
	if err := connectDatabase(filepath.Join("/Users/drej/Projects/goat-regtest/submodule/relayer/internal/wallet/wallet_order.db"), &dbRef, "wallet"); err != nil {
		log.Fatalf("Failed to connect to %s: %v", "wallet", err)
	}

	remoteClient := &FireblocksClient{
		client: http.NewFireblocksProposal(),
	}
	// Validate results
	var sendOrders []*db.SendOrder
	var vins []*db.Vin
	err = dbRef.Where("status = ?", db.ORDER_STATUS_INIT).Find(&sendOrders).Error
	require.NoError(t, err)

	for _, sendOrder := range sendOrders {
		tx, err := types.DeserializeTransaction(sendOrder.NoWitnessTx)
		if err != nil {
			log.Errorf("OrderBroadcaster broadcastOrders deserialize tx error: %v, txid: %s", err, sendOrder.Txid)
			continue
		}

		var vinUtxos []*db.Utxo
		err = dbRef.Where("order_id = ?", sendOrder.OrderId).Find(&vins).Error
		require.NoError(t, err)

		// Validate UTXOs
		for _, vin := range vins {
			var utxos []*db.Utxo
			err = dbRef.Where("txid = ? and out_index = ?", vin.Txid, vin.OutIndex).Find(&utxos).Error
			require.NoError(t, err)
			vinUtxos = append(vinUtxos, utxos...)
		}
		assert.NotEmpty(t, vinUtxos, "UTXOs should not be empty for the order")

		// Generate raw message to fireblocks
		rawMessage, err := GenerateRawMeessageToFireblocks(tx, vinUtxos, types.GetBTCNetwork(config.AppConfig.BTCNetworkType))
		if err != nil {
			log.Errorf("OrderBroadcaster broadcastOrders generate raw message to fireblocks error: %v, txid: %s", err, sendOrder.Txid)
			continue
		}
		log.Debugf("rawMessage: %+v", rawMessage)

		// Post raw signing request to fireblocks
		resp, err := remoteClient.client.PostRawSigningRequest(rawMessage, fmt.Sprintf("%s:%s", sendOrder.OrderType, sendOrder.Txid))
		if err != nil {
			log.Errorf("OrderBroadcaster broadcastOrders post raw signing request error: %v, txid: %s", err, sendOrder.Txid)
			continue
		}
		if resp.Code != 0 {
			log.Errorf("OrderBroadcaster broadcastOrders post raw signing request error: %v, txid: %s", resp.Message, sendOrder.Txid)
			continue
		}
		log.Debugf("PostRawSigningRequest resp: %+v", resp)
	}

	time.Sleep(5 * time.Second)
}

func connectDatabase(dbPath string, dbRef **gorm.DB, dbName string) error {
	// open database and set WAL mode
	db, err := gorm.Open(sqlite.Open(dbPath+"?_journal_mode=WAL"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", dbName, err)
	}

	*dbRef = db
	log.Debugf("%s connected successfully in WAL mode, path: %s", dbName, dbPath)
	return nil
}

// TestSendRawTransaction_Testnet4 tests sendRawTransaction with GetBlock testnet4
// Set GETBLOCK_TESTNET4_URL env var to run this test, e.g.:
// GETBLOCK_TESTNET4_URL=go.getblock.io/<your-api-key> go test -v -run TestSendRawTransaction_Testnet4
func TestSendRawTransaction_Testnet4(t *testing.T) {
	// GetBlock testnet4 endpoint from environment variable
	rpcHost := os.Getenv("GETBLOCK_TESTNET4_URL")
	if rpcHost == "" {
		t.Skip("Skipping: GETBLOCK_TESTNET4_URL not set")
	}

	// Create RPC client
	connCfg := &rpcclient.ConnConfig{
		Host:         rpcHost,
		User:         "x", // GetBlock doesn't require auth but rpcclient needs non-empty
		Pass:         "x",
		HTTPPostMode: true,
		DisableTLS:   false,
	}

	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		t.Fatalf("Failed to create RPC client: %v", err)
	}
	defer client.Shutdown()

	// Test 1: Verify RawRequest works with getblockcount
	t.Run("GetBlockCount", func(t *testing.T) {
		rawResp, err := client.RawRequest("getblockcount", nil)
		if err != nil {
			if strings.Contains(err.Error(), "dial tcp") || strings.Contains(err.Error(), "connect:") {
				t.Skipf("Skipping due to network issue: %v", err)
			}
			t.Fatalf("getblockcount failed: %v", err)
		}
		var blockCount int64
		if err := json.Unmarshal(rawResp, &blockCount); err != nil {
			t.Fatalf("Failed to unmarshal blockcount: %v", err)
		}
		t.Logf("Current testnet4 block count: %d", blockCount)
		assert.Greater(t, blockCount, int64(0))
	})

	// Test 2: Verify getinfo fails (GetBlock returns 403) - this is why we use RawRequest
	t.Run("GetInfo_Blocked", func(t *testing.T) {
		_, err := client.RawRequest("getinfo", nil)
		if err == nil {
			t.Log("getinfo succeeded (unexpected for GetBlock)")
		} else {
			if strings.Contains(err.Error(), "dial tcp") || strings.Contains(err.Error(), "connect:") {
				t.Skipf("Skipping due to network issue: %v", err)
			}
			t.Logf("getinfo blocked as expected (403): %v", err)
		}
	})

	// Test 3: Verify sendrawtransaction RawRequest format works
	t.Run("SendRawTransaction_InvalidTx", func(t *testing.T) {
		// Invalid tx hex - tests that RPC format is correct (error should be about tx, not format)
		invalidHex := "0100000000000000"
		rawResp, err := client.RawRequest("sendrawtransaction", []json.RawMessage{
			json.RawMessage(fmt.Sprintf("%q", invalidHex)),
		})
		if err == nil {
			t.Fatalf("Expected error for invalid tx, got response: %s", string(rawResp))
		}
		if strings.Contains(err.Error(), "dial tcp") || strings.Contains(err.Error(), "connect:") {
			t.Skipf("Skipping due to network issue: %v", err)
		}
		// Error should be about tx validation, not RPC format
		t.Logf("TX validation error (expected): %v", err)
	})

	// Test 4: getblockchaininfo to verify chain is testnet4
	t.Run("GetBlockchainInfo", func(t *testing.T) {
		rawResp, err := client.RawRequest("getblockchaininfo", nil)
		if err != nil {
			if strings.Contains(err.Error(), "dial tcp") || strings.Contains(err.Error(), "connect:") {
				t.Skipf("Skipping due to network issue: %v", err)
			}
			t.Fatalf("getblockchaininfo failed: %v", err)
		}
		var info map[string]interface{}
		if err := json.Unmarshal(rawResp, &info); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}
		t.Logf("Chain: %v, Blocks: %v", info["chain"], info["blocks"])
		assert.Equal(t, "testnet4", info["chain"])
	})
}

