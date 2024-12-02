package wallet

import (
	"testing"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestBTCClient(t *testing.T) {
	t.Skip("This is for verifying the BTC rpc node, skipping the test for prod")

	tempDir := t.TempDir()
	t.Setenv("DB_DIR", tempDir)
	t.Setenv("L2_PRIVATE_KEY", "e9ccd0ec6bb77c263dc46c0f81962c0b378a67befe089e90ef81e96a4a4c5bc5")
	t.Setenv("BTC_RPC", "127.0.0.1:18332")
	t.Setenv("BTC_RPC_USER", "goat")
	t.Setenv("BTC_RPC_PASS", "goat")
	t.Setenv("BTC_NETWORK_TYPE", "testnet3")
	// Initialize config module
	config.InitConfig()

	// Modify connection configuration
	connConfig := &rpcclient.ConnConfig{
		Host:         config.AppConfig.BTCRPC,
		User:         config.AppConfig.BTCRPC_USER,
		Pass:         config.AppConfig.BTCRPC_PASS,
		HTTPPostMode: true,
		DisableTLS:   false,
	}

	// Create new RPC client
	btcClient, err := rpcclient.New(connConfig, nil)
	if err != nil {
		t.Fatalf("Failed to create Bitcoin client: %v", err)
	}
	defer btcClient.Shutdown()

	// Get block height
	height, err := btcClient.GetBlockCount()
	if err != nil {
		t.Errorf("Failed to get block height: %v", err)
	} else {
		t.Logf("Block height: %d", height)
		assert.Greater(t, height, int64(0), "Block height should be greater than 0")
	}

	// Get network information
	info, err := btcClient.GetNetworkInfo()
	if err != nil {
		t.Errorf("Failed to get network information: %v", err)
	} else {
		t.Logf("Network information: %+v", info)
		assert.NotNil(t, info, "Network information should not be nil")
	}

	feeEstimate, err := btcClient.EstimateSmartFee(1, &btcjson.EstimateModeConservative)
	if err != nil {
		t.Errorf("Failed to estimate smart fee: %v", err)
	}
	satoshiPerVByte := uint64((*feeEstimate.FeeRate * 1e8) / 1000)
	t.Logf("Estimate smart fee: %+v, satoshi per vbyte: %d", feeEstimate, satoshiPerVByte)

	blockHash, err := btcClient.GetBlockHash(height)
	if err != nil {
		t.Errorf("Failed to get block hash at height %d: %v", height, err)
	}

	block, err := btcClient.GetBlock(blockHash)
	if err != nil {
		t.Errorf("Failed to get block at height %d: %v", height, err)
	}
	networkParams := types.GetBTCNetwork(config.AppConfig.BTCNetworkType)
	if err != nil {
		t.Errorf("Failed to get network params: %v", err)
	}
	// Test verification function
	err = types.VerifyBlockSPV(types.BtcBlockExt{
		MsgBlock:    *block,
		BlockNumber: uint64(height),
	})
	if err != nil {
		t.Errorf("SPV verification failed: %v", err)
	}

	for _, tx := range block.Transactions {
		for idx, vin := range tx.TxIn {
			_, addresses, _, err := txscript.ExtractPkScriptAddrs(vin.SignatureScript, networkParams)
			if err != nil {
				t.Logf("Extracting input address %d err, %v", idx, err)
				continue
			}
			if len(addresses) == 0 {
				t.Logf("Extracting input address %d nil, txid: %s", idx, tx.TxID())
				continue
			}
			t.Logf("Extracted input address %d: %s, txid: %s", idx, addresses[0].EncodeAddress(), tx.TxID())
		}

		for idx, vout := range tx.TxOut {
			_, addresses, _, err := txscript.ExtractPkScriptAddrs(vout.PkScript, networkParams)
			if err != nil {
				t.Logf("Extracting output address %d err, %v", idx, err)
				continue
			}
			if len(addresses) == 0 {
				t.Logf("Extracting output address %d nil, txid: %s", idx, tx.TxID())
				continue
			}
			t.Logf("Extracted output address %d: %s, txid: %s", idx, addresses[0].EncodeAddress(), tx.TxID())
		}
	}
	t.Logf("Block: %+v", block)
}
