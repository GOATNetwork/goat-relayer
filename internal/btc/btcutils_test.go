package btc

import (
	"bytes"
	"encoding/hex"
	"testing"

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

	merkleRoot, proofBytes, txIndex, err := GenerateSPVProof(tx.TxHash().String(), txHashes)
	if err != nil {
		return false
	}

	// Verify the generated proof
	targetTxHash, _ := chainhash.NewHashFromStr(txHashes[txIndex])

	return bitcointypes.VerifyMerkelProof(targetTxHash[:], merkleRoot[:], proofBytes, txIndex)
}
