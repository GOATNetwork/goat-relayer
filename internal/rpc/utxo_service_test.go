package rpc

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/btc"
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
