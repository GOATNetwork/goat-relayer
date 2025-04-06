package layer2

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/layer2/abis"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/stretchr/testify/assert"
)

// Test if filterEvmEvents method can scan TaskCreated event in block 48
func TestFilterEvmEvents_Block48_TaskCreated(t *testing.T) {
	t.Skip("This is for local regtest test, skipping the test for prod")
	// Connect to local Ethereum node
	client, err := ethclient.Dial("http://localhost:8545")
	if err != nil {
		t.Fatalf("Failed to connect to Ethereum node: %v", err)
	}
	defer client.Close()

	tempdir := t.TempDir()
	t.Setenv("DB_DIR", tempdir)
	t.Setenv("CONTRACT_TASK_MANAGER", "0x6827D591faDa19A1274Df0Ab2608901AaaEA14C9")
	// Initialize config module
	config.InitConfig()

	// Set up test data
	blockHash := "0x55488626d35face7f091a5f530b9c6b83592dee1041e750035dbda299cc391a8"

	// Parse ABI
	contractTaskManagerAbi, err := abi.JSON(strings.NewReader(abis.TaskManagerContractABI))
	if err != nil {
		t.Fatalf("Failed to parse ABI: %v", err)
	}

	// Create contract instance
	contractAddr := common.HexToAddress(config.AppConfig.ContractTaskManager)
	contractTaskManager, err := abis.NewTaskManagerContract(contractAddr, client)
	if err != nil {
		t.Fatalf("Failed to create contract instance: %v", err)
	}

	// Create context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Initialize database manager
	dbm := db.NewDatabaseManager()

	// Initialize state manager
	stateManager := state.InitializeState(dbm)

	// Create Layer2Listener instance
	lis := &Layer2Listener{
		ethClient:              client,
		contractTaskManagerAbi: &contractTaskManagerAbi,
		contractTaskManager:    contractTaskManager,
		state:                  stateManager,
	}

	// Execute test
	err = lis.filterEvmEvents(ctx, blockHash)

	// Verify results
	assert.NoError(t, err, "filterEvmEvents should execute successfully")

	// Verify if TaskCreated event was successfully scanned
	// Note: This test depends on data for block 48 being available on the local Ethereum node
	// If the node doesn't have data for this block, the test might fail

	// Print contract address for debugging
	t.Logf("Contract address: %s", config.AppConfig.ContractTaskManager)

	// Print block hash for debugging
	t.Logf("Block hash: %s", blockHash)

	// Print transaction hash for debugging
	t.Logf("Transaction hash: 0x77eead679c3daf6716fa6a9e37d3ffaa3a2b1512fca9c1185e2ba56f5cbcb8f8")
}
