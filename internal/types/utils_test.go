package types

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	bitcointypes "github.com/goatnetwork/goat/x/bitcoin/types"
	"github.com/stretchr/testify/assert"
)

func TestCorrectTxHash(t *testing.T) {
	txHashes := []string{
		"6f33de3f5347f832f0f5ad39b0bc4309ec6a9de586d6763b733e1fbecbd9c8d8",
		"43a434c639ab3884361f168870b658d331e8dbc9dfbf05af093ee07c20ab766f",
		"915cf91cef8a56c1284616ad149b6ee0674360ed09c51e10b2de5b9ec36b24d4",
	}

	// correct tx hash
	rawTxHex := "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016f00ffffffff02706e0a2a01000000160014f890a762934d98c2f4cabbb829863de03fd7e7b00000000000000000266a24aa21a9edc1c1fdca70dc22518c456c4125655712e481c401137aad186c2eac5851c077b80120000000000000000000000000000000000000000000000000000000000000000000000000"
	assert.True(t, processTransaction(rawTxHex, txHashes))
}

func TestWrongTxHash(t *testing.T) {
	txHashes := []string{
		"6f33de3f5347f832f0f5ad39b0bc4309ec6a9de586d6763b733e1fbecbd9c8d8",
		"43a434c639ab3884361f168870b658d331e8dbc9dfbf05af093ee07c20ab766f",
		"915cf91cef8a56c1284616ad149b6ee0674360ed09c51e10b2de5b9ec36b24d4",
	}
	// wrong tx hash which modifies the raw tx
	rawTxHex := "021011111101010000000000000000000000000000000000000000000000000000000000000000ffffffff03016f001111111102706e0a2a01000000160014f890a762934d98c2f4cabbb829863de03fd7e7b00000000000000000266a24aa21a9edc1c1fdca70dc22518c456c4125655712e481c401137aad186c2eac5851c077b80120000000000000000000000000000000000000000000000000000000000000000000000000"
	assert.False(t, processTransaction(rawTxHex, txHashes))
}

func processTransaction(rawTxHex string, txHashes []string) bool {
	rawTxBytes, err := hex.DecodeString(rawTxHex)
	if err != nil {
		return false
	}

	if err != nil {
		return false
	}

	var tx wire.MsgTx
	err = tx.Deserialize(bytes.NewReader(rawTxBytes))
	if err != nil {
		return false
	}

	merkleRoot, proofBytes, txIndex, err := GenerateSPVProof(tx.TxID(), txHashes)
	if err != nil {
		return false
	}

	// Verify the generated proof
	targetTxHash, _ := chainhash.NewHashFromStr(txHashes[txIndex])

	return bitcointypes.VerifyMerkelProof(targetTxHash[:], merkleRoot[:], proofBytes, uint32(txIndex))
}

func TestGenerateV0P2WSHAddress(t *testing.T) {
	// Prepare test data
	pubKeyHex := "0383560def84048edefe637d0119a4428dd12a42765a118b2bf77984057633c50e"
	pubKey, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}

	evmAddress := "0x29cF29d4b2CD6Db07f6db43243e8E43fE3DC468e"
	net := &chaincfg.TestNet3Params

	// Call function to generate P2WSH address
	p2wshAddress, err := GenerateV0P2WSHAddress(pubKey, evmAddress, net)
	if err != nil {
		t.Fatalf("Failed to generate P2WSH address: %v", err)
	}

	// Validate the generated address
	if p2wshAddress == nil {
		t.Fatal("Generated P2WSH address is nil")
	}

	// Check if the address prefix is correct (testnet3 P2WSH addresses start with "tb1q")
	if !strings.HasPrefix(p2wshAddress.EncodeAddress(), "tb1q") {
		t.Errorf("Generated address prefix is incorrect, expected to start with 'tb1q', actual: %s", p2wshAddress.EncodeAddress())
	}

	// Print the generated address
	t.Logf("Generated P2WSH address: %s", p2wshAddress.EncodeAddress())
}

func TestGenerateTimeLockP2WSHAddress(t *testing.T) {
	pubKeyHex := "0383560def84048edefe637d0119a4428dd12a42765a118b2bf77984057633c50e"
	pubKey, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}

	lockTime := time.Now().Add(time.Hour * 24 * 30)
	net := &chaincfg.TestNet3Params

	p2wshAddress, err := GenerateTimeLockP2WSHAddress(pubKey, lockTime, net)
	if err != nil {
		t.Fatalf("Failed to generate P2WSH address: %v", err)
	}

	// Validate the generated address
	if p2wshAddress == nil {
		t.Fatal("Generated P2WSH address is nil")
	}

	// Check if the address prefix is correct (testnet3 P2WSH addresses start with "tb1q")
	if !strings.HasPrefix(p2wshAddress.EncodeAddress(), "tb1q") {
		t.Errorf("Generated address prefix is incorrect, expected to start with 'tb1q', actual: %s", p2wshAddress.EncodeAddress())
	}

	// Print the generated address
	t.Logf("Generated P2WSH address: %s", p2wshAddress.EncodeAddress())
}
