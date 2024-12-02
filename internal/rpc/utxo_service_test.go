package rpc

import (
	"testing"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/stretchr/testify/assert"
)

func TestAddUnconfirmDeposit(t *testing.T) {
	// Create temporary test directory
	tempDir := t.TempDir()
	t.Setenv("DB_DIR", tempDir)

	// Initialize config module
	config.InitConfig()

	// Initialize State
	// Initialize DatabaseManager
	dbm := db.NewDatabaseManager()

	// Initialize State
	s := state.InitializeState(dbm)

	// Test data
	txID := "testTxID"
	rawTx := "testRawTx"
	evmAddress := "testEvmAddress"
	signVersion := uint32(1)

	// Test adding unconfirmed deposit
	err := s.AddUnconfirmDeposit(txID, rawTx, evmAddress, signVersion, 0, 0)
	assert.NoError(t, err)

	// // Verify if the deposit was correctly added
	// deposit, exists := s.GetUnconfirmedDeposit(txID)
	// assert.True(t, exists)
	// assert.Equal(t, rawTx, deposit.RawTransaction)
	// assert.Equal(t, evmAddress, deposit.EvmAddress)

	// // Test adding duplicate deposit
	// err = s.AddUnconfirmDeposit(txID, rawTx, evmAddress)
	// assert.Error(t, err) // Should return an error because the deposit already exists

	// Test adding a different deposit
	err = s.AddUnconfirmDeposit("anotherTxID", "anotherRawTx", "anotherEvmAddress", uint32(0), 0, 0)
	assert.NoError(t, err)
}
