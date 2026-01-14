package btc

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getTestClient returns an RPC client from environment
// Set BTC_RPC and optionally BTC_RPC_API_KEY.
func getTestClient(t *testing.T) *rpcclient.Client {
	return newRPCClientFromEnv(t, "BTC_RPC")
}

// newRPCClientFromEnv builds a client using the supplied RPC URL environment variable.
func newRPCClientFromEnv(t *testing.T, rpcEnv string) *rpcclient.Client {
	rpcURL := os.Getenv(rpcEnv)
	if rpcURL == "" {
		t.Skipf("Skipping: %s not set", rpcEnv)
	}

	apiKey := os.Getenv("BTC_RPC_API_KEY")

	disableTLS := true
	rpcHost := rpcURL
	if parsed, err := url.Parse(rpcHost); err == nil && parsed.Host != "" {
		// Preserve path for APIs that keep the endpoint in the URL.
		rpcHost = parsed.Host + parsed.Path
		disableTLS = parsed.Scheme != "https"
	}
	rpcHost = strings.TrimSuffix(rpcHost, "/")
	// Add default port if not specified
	if !strings.Contains(rpcHost, ":") {
		if disableTLS {
			rpcHost = rpcHost + ":80"
		} else {
			rpcHost = rpcHost + ":443"
		}
	}

	connCfg := &rpcclient.ConnConfig{
		Host:         rpcHost,
		User:         "x",
		Pass:         "x",
		HTTPPostMode: true,
		DisableTLS:   disableTLS,
	}

	if apiKey != "" {
		connCfg.ExtraHeaders = map[string]string{
			"x-api-key": apiKey,
		}
	}

	client, err := rpcclient.New(connCfg, nil)
	require.NoError(t, err)
	t.Cleanup(func() { client.Shutdown() })

	return client
}

func fetchBlockHash(t *testing.T, client *rpcclient.Client) (*chainhash.Hash, int64) {
	t.Helper()

	result, err := client.RawRequest("getblockcount", nil)
	require.NoError(t, err)

	var blockCount int64
	require.NoError(t, json.Unmarshal(result, &blockCount))

	testHeight := blockCount - 100
	if testHeight < 1 {
		testHeight = 1
	}

	blockHash, err := client.GetBlockHash(testHeight)
	require.NoError(t, err)

	return blockHash, testHeight
}

func fetchTxID(t *testing.T, client *rpcclient.Client) string {
	t.Helper()

	blockHash, _ := fetchBlockHash(t, client)
	blockVerbose, err := client.GetBlockVerbose(blockHash)
	require.NoError(t, err)
	require.NotEmpty(t, blockVerbose.Tx)

	return blockVerbose.Tx[0]
}

// TestRPC_RawRequest_GetBlockCount tests RawRequest("getblockcount") - used in notifier.go
func TestRPC_RawRequest_GetBlockCount(t *testing.T) {
	client := getTestClient(t)

	result, err := client.RawRequest("getblockcount", nil)
	require.NoError(t, err)

	var blockCount int64
	require.NoError(t, json.Unmarshal(result, &blockCount))
	assert.Greater(t, blockCount, int64(0))

	t.Logf("Block count: %d", blockCount)
}

// TestRPC_GetBlockHash tests client.GetBlockHash - used in rpc_service.go and notifier.go
func TestRPC_GetBlockHash(t *testing.T) {
	client := getTestClient(t)

	result, err := client.RawRequest("getblockcount", nil)
	require.NoError(t, err)

	var blockCount int64
	require.NoError(t, json.Unmarshal(result, &blockCount))

	testHeight := blockCount - 100
	if testHeight < 1 {
		testHeight = 1
	}

	// Test GetBlockHash - this is what business code uses
	blockHash, err := client.GetBlockHash(testHeight)
	require.NoError(t, err)
	assert.NotNil(t, blockHash)
	assert.Len(t, blockHash.String(), 64)

	t.Logf("Block %d hash: %s", testHeight, blockHash.String())
}

// TestRPC_GetBlock tests client.GetBlock - used in rpc_service.go and notifier.go
func TestRPC_GetBlock(t *testing.T) {
	client := getTestClient(t)

	blockHash, testHeight := fetchBlockHash(t, client)

	// Test GetBlock - returns *wire.MsgBlock
	block, err := client.GetBlock(blockHash)
	require.NoError(t, err)
	assert.NotNil(t, block)
	assert.NotNil(t, block.Header)
	assert.NotEmpty(t, block.Transactions)

	// Verify block hash matches
	assert.Equal(t, blockHash.String(), block.BlockHash().String())

	t.Logf("Block %d: hash=%s, tx_count=%d, version=%d",
		testHeight, block.BlockHash().String(), len(block.Transactions), block.Header.Version)
}

// TestRPC_GetBlockVerbose tests client.GetBlockVerbose - used in rpc_service.go and withdraw_broadcast.go
func TestRPC_GetBlockVerbose(t *testing.T) {
	client := getTestClient(t)

	blockHash, testHeight := fetchBlockHash(t, client)
	blockVerbose, err := client.GetBlockVerbose(blockHash)
	require.NoError(t, err)
	assert.NotNil(t, blockVerbose)
	assert.Equal(t, blockHash.String(), blockVerbose.Hash)
	assert.Equal(t, testHeight, blockVerbose.Height)
	assert.Greater(t, blockVerbose.Confirmations, int64(0))
	assert.NotEmpty(t, blockVerbose.Tx)
	assert.NotEmpty(t, blockVerbose.MerkleRoot)
	assert.Greater(t, blockVerbose.Time, int64(0))

	t.Logf("Block %d verbose: hash=%s, confirmations=%d, tx_count=%d, time=%d",
		blockVerbose.Height, blockVerbose.Hash, blockVerbose.Confirmations, len(blockVerbose.Tx), blockVerbose.Time)
}

// TestRPC_GetRawTransactionVerbose tests client.GetRawTransactionVerbose - used in rpc_service.go and withdraw_broadcast.go
func TestRPC_GetRawTransactionVerbose(t *testing.T) {
	client := getTestClient(t)

	txID := fetchTxID(t, client)
	txHash, err := chainhash.NewHashFromStr(txID)
	require.NoError(t, err)

	txResult, err := client.GetRawTransactionVerbose(txHash)
	require.NoError(t, err)
	assert.NotNil(t, txResult)
	assert.Equal(t, txID, txResult.Txid)
	assert.NotEmpty(t, txResult.BlockHash)
	assert.Greater(t, txResult.Confirmations, uint64(0))
	assert.Greater(t, txResult.Blocktime, int64(0))

	t.Logf("Transaction: txid=%s, blockhash=%s, confirmations=%d, blocktime=%d",
		txResult.Txid, txResult.BlockHash, txResult.Confirmations, txResult.Blocktime)
}

// TestRPC_SendRawTransaction tests client.SendRawTransaction error handling - used in withdraw_broadcast.go
func TestRPC_SendRawTransaction(t *testing.T) {
	client := getTestClient(t)

	// Test with invalid transaction - should return error
	// We can't test successful broadcast without a valid funded transaction
	invalidHex := "0100000000000000"
	hexJSON, _ := json.Marshal(invalidHex)

	_, err := client.RawRequest("sendrawtransaction", []json.RawMessage{hexJSON})
	require.Error(t, err)

	// Verify error is about transaction validation
	errStr := err.Error()
	assert.True(t,
		strings.Contains(errStr, "decode") ||
			strings.Contains(errStr, "deserialize") ||
			strings.Contains(errStr, "-22") ||
			strings.Contains(errStr, "TX") ||
			strings.Contains(errStr, "transaction"),
		"Expected tx validation error, got: %s", errStr)

	t.Logf("SendRawTransaction error (expected): %v", err)
}
