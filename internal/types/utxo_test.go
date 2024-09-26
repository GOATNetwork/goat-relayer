package types

import (
	"bytes"
	"encoding/hex"
	relayer "github.com/goatnetwork/goat/x/relayer/types"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

func TestIsUtxoGoatDepositV1WithRawTx(t *testing.T) {
	// Decode the provided raw transaction
	rawTx := "020000000001013b16081931db7633dde8e0475385e607de9d8f3b372a219115179858787517a30200000000fdffffff0380969800000000001600149759ed6aae6ade43ae6628a943a39974cd21c5df00000000000000001a6a184754543070997970c51812dc3a010c7d01b50e0d17dc79c8ca649b1c00000000160014059ce0647de86cf966dfa4656a08530eb8f26772024730440220183ac1ff33c5ad358069ec79a030c3329078d02d77f3ae19d0226810bad74d6d02203c61ba76f590380cf61b4cfc188a0de718c801b4eb24d58dbbf9ad928879449901210361e82e71277ea205814b1cb69777abe5fc417c03d4d39829cefb8f92da08b1fc00000000"
	txBytes, err := hex.DecodeString(rawTx)
	if err != nil {
		t.Fatalf("Failed to decode raw transaction: %v", err)
	}

	// Deserialize the transaction
	tx := wire.NewMsgTx(wire.TxVersion)
	err = tx.Deserialize(bytes.NewReader(txBytes))
	if err != nil {
		t.Fatalf("Failed to deserialize raw transaction: %v", err)
	}

	// Decode the provided public key (address)
	pubKeyHex := "0383560def84048edefe637d0119a4428dd12a42765a118b2bf77984057633c50e"
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}

	network := &chaincfg.RegressionNetParams
	p2pkhAddress, err := GenerateP2PKHAddress(pubKeyBytes, network)
	if err != nil {
		t.Fatalf("Gen P2PKH address err %v", err)
	}
	p2wpkhAddress, err := GenerateP2WPKHAddress(pubKeyBytes, network)
	if err != nil {
		t.Fatalf("Gen P2WPKH address err %v", err)
	}
	t.Logf("p2pkhAddress: %s", p2pkhAddress.EncodeAddress())
	t.Logf("p2wpkhAddress: %s", p2wpkhAddress.EncodeAddress())

	// Mock tssAddress with the same address as TxOut[0]
	tssAddress := []btcutil.Address{p2pkhAddress, p2wpkhAddress}

	// Test the transaction using IsUtxoGoatDepositV1
	isDepositV1, evmAddress := IsUtxoGoatDepositV1(tx, tssAddress, network)
	if !isDepositV1 {
		t.Errorf("Expected transaction to be a valid GOAT deposit, got invalid")
	}
	t.Logf("Extract evmAddress: %s", evmAddress)
	assert.NotEqual(t, evmAddress, (common.Address{}).Hex())
}

func TestIsUtxoGoatDepositV0WithRawTx(t *testing.T) {
	// Decode the provided raw transaction
	rawTx := "020000000001016ad4d126b6482f66de18beb8165d3b4db35f10e3fae8b6e2e3c64c02683c74ce0000000000fdffffff0200e1f505000000002200203d8123c9f1e87f4aa92b981b83ddc34674b2136e9b5f01f92fcd3db33832fab258bb0d24010000001600140e4be049c2caba19d3d31af704f9037c0f9945e0024730440220552efa15059bc7ee2ea579eead60eb8e03462f889742fc26712a2dd47473a98f02200cd43cc2ccab7a04e4527dd9443c8ef5ddd5e6e841846046935b538fb87843c6012102da128984b7468a3346f1f6758c584cc2ed2597649296c63d801d5d78e5f38bf700000000"
	txBytes, err := hex.DecodeString(rawTx)
	if err != nil {
		t.Fatalf("Failed to decode raw transaction: %v", err)
	}

	// Deserialize the transaction
	tx := wire.NewMsgTx(wire.TxVersion)
	err = tx.Deserialize(bytes.NewReader(txBytes))
	if err != nil {
		t.Fatalf("Failed to deserialize raw transaction: %v", err)
	}

	// Decode the provided public key (address)
	pubKeyHex := "0383560def84048edefe637d0119a4428dd12a42765a118b2bf77984057633c50e"
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}

	// EVM address for testing
	evmAddress := "70997970C51812dc3A010C7d01b50e0d17dc79C8"

	// Generate the deposit address
	network := &chaincfg.RegressionNetParams
	p2wshAddr, err := GenerateP2WSHAddress(pubKeyBytes, evmAddress, network)
	if err != nil {
		t.Fatalf("Gen P2WSH address err %v", err)
	}
	t.Logf("p2wshAddress: %s", p2wshAddr.EncodeAddress())

	// Decode the provided public key (address)
	pubKeyHex2 := "000383560def84048edefe637d0119a4428dd12a42765a118b2bf77984057633c50e"
	pubKeyBytes2, err := hex.DecodeString(pubKeyHex2)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}
	key := relayer.DecodePublicKey(pubKeyBytes2)

	// Test the transaction using IsUtxoGoatDepositV0
	isDepositV0 := IsUtxoGoatDepositV0(key, tx, evmAddress, p2wshAddr, network)
	if !isDepositV0 {
		t.Errorf("Expected transaction to be a valid GOAT deposit, got invalid")
	}
}
