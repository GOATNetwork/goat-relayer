package rpc

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/btc"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/stretchr/testify/assert"
)

func TestVerifyTransaction(t *testing.T) {
	// Test case 1: Valid transaction
	validRawTx := "02000000000101c33f58055925205fe7ecf23f37323d85ac0c86cd07ff2a5ddef9e24fcf5efbb80200000000fdffffff03e803000000000000160014240cbf5ca7c69e2f79c27dc2eb0fc58853b0aff300000000000000001a6a1847545430f39fd6e51aad88f6f4ce6ab8827279cfffb92266204e000000000000160014059ce0647de86cf966dfa4656a08530eb8f267720247304402207bf76a20f86c8ca8f167dfd22334323da2077037f1694f220c53f153596baad102206b2ab20e207bbd10dabb3f6fb64aad89825ac48635b6b9e5531d1235523119a601210361e82e71277ea205814b1cb69777abe5fc417c03d4d39829cefb8f92da08b1fc00000000"
	evmAddress := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	txHash := "f907189b2486178751aca399d7ad7a06deb9d36086c3efc61e5cadadf32b3188"
	rawTxBytes, err := hex.DecodeString(validRawTx)
	if err != nil {
		t.Fatalf("Failed to decode raw transaction: %v", err)
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(rawTxBytes)); err != nil {
		t.Fatalf("Failed to deserialize transaction: %v", err)
	}

	err = btc.VerifyTransaction(tx, txHash, evmAddress)
	if err != nil {
		t.Errorf("VerifyTransaction failed for valid transaction: %v", err)
	}
}

func TestAddUnconfirmDeposit(t *testing.T) {
	// Create temporary test directory
	tempDir := t.TempDir()
	t.Setenv("DB_DIR", tempDir)
	t.Setenv("L2_PRIVATE_KEY", "e9ccd0ec6bb77c263dc46c0f81962c0b378a67befe089e90ef81e96a4a4c5bc5")

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

	// Test adding unconfirmed deposit
	err := s.AddUnconfirmDeposit(txID, rawTx, evmAddress)
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
	err = s.AddUnconfirmDeposit("anotherTxID", "anotherRawTx", "anotherEvmAddress")
	assert.NoError(t, err)
}
