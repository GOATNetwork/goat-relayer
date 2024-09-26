package wallet

import (
	"bytes"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestSpentP2wsh(t *testing.T) {
	privKeyBytes, _ := hex.DecodeString("e9ccd0ec6bb77c263dc46c0f81962c0b378a67befe089e90ef81e96a4a4c5bc5")
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)
	evmAddress := "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
	if strings.HasPrefix(evmAddress, "0x") {
		evmAddress = evmAddress[2:]
	}

	evmAddress_, _ := hex.DecodeString(evmAddress)

	evmAddresses := [][]byte{
		evmAddress_,
		evmAddress_,
	}

	prevTxIds := []string{
		"82559ad1e71bda315c7b87c8ee0d4d406063c108ad3d6c4ce0acbf2fcdb1e376",
		"23a8ddd6345fa69bff8196effe731781187d9977ec4c6b8c59631650443709b7",
	}

	prevTxouts := []int{
		0,
		1,
	}
	amounts := []int64{
		1e8,
		1e8,
	}

	rawTxHex, err := SpentP2wsh(&chaincfg.RegressionNetParams, privKey, evmAddresses, prevTxIds, prevTxouts, amounts,
		1e3)
	assert.Nil(t, err)
	assert.NotEmpty(t, rawTxHex)

	txBytes, err := hex.DecodeString(rawTxHex)
	assert.Nil(t, err)

	tx := wire.NewMsgTx(2)
	err = tx.Deserialize(bytes.NewReader(txBytes))
	assert.Nil(t, err)

	assert.NotNil(t, tx.TxOut)
	assert.NotNil(t, tx.TxIn)
	assert.Equal(t, len(tx.TxIn), len(evmAddresses))
}
