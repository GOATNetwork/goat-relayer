package wallet

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

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
