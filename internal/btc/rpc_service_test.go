package btc

import (
	"encoding/json"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
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

func getEnvOrSkip(t *testing.T, key string) string {
	t.Helper()

	value := os.Getenv(key)
	if value == "" {
		t.Skipf("Skipping: %s not set", key)
	}
	return value
}

func getEnvInt64OrSkip(t *testing.T, key string) int64 {
	t.Helper()

	value := getEnvOrSkip(t, key)
	parsed, err := strconv.ParseInt(value, 10, 64)
	require.NoError(t, err, "invalid %s", key)
	return parsed
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

	testHeight := getEnvInt64OrSkip(t, "BTC_RPC_HEIGHT")

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

	blockHash := getEnvOrSkip(t, "BTC_RPC_BLOCK_HASH")
	testHeight := getEnvInt64OrSkip(t, "BTC_RPC_HEIGHT")
	parsedHash, err := chainhash.NewHashFromStr(blockHash)
	require.NoError(t, err)

	// Test GetBlock - returns *wire.MsgBlock
	block, err := client.GetBlock(parsedHash)
	require.NoError(t, err)
	assert.NotNil(t, block)
	assert.NotNil(t, block.Header)
	assert.NotEmpty(t, block.Transactions)

	// Verify block hash matches
	assert.Equal(t, parsedHash.String(), block.BlockHash().String())

	t.Logf("Block %d: hash=%s, tx_count=%d, version=%d",
		testHeight, block.BlockHash().String(), len(block.Transactions), block.Header.Version)
}

// TestRPC_GetBlockVerbose tests client.GetBlockVerbose - used in rpc_service.go and withdraw_broadcast.go
func TestRPC_GetBlockVerbose(t *testing.T) {
	client := getTestClient(t)

	blockHash := getEnvOrSkip(t, "BTC_RPC_BLOCK_HASH")
	testHeight := getEnvInt64OrSkip(t, "BTC_RPC_HEIGHT")
	parsedHash, err := chainhash.NewHashFromStr(blockHash)
	require.NoError(t, err)

	blockVerbose, err := client.GetBlockVerbose(parsedHash)
	require.NoError(t, err)
	assert.NotNil(t, blockVerbose)
	assert.Equal(t, blockHash, blockVerbose.Hash)
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

	txID := getEnvOrSkip(t, "BTC_RPC_TXID")
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

// TestRPC_GetBlockVerboseTx tests client.GetBlockVerboseTx - used in deposit.go
func TestRPC_GetBlockVerboseTx(t *testing.T) {
	client := getTestClient(t)

	blockHash := getEnvOrSkip(t, "BTC_RPC_BLOCK_HASH")
	parsedHash, err := chainhash.NewHashFromStr(blockHash)
	require.NoError(t, err)

	blockVerbose, err := client.GetBlockVerboseTx(parsedHash)
	require.NoError(t, err)
	assert.NotNil(t, blockVerbose)
	assert.Equal(t, blockHash, blockVerbose.Hash)
	assert.Greater(t, blockVerbose.Height, int64(0))
	assert.NotEmpty(t, blockVerbose.Tx)
}

// TestRPC_GetRawTransaction tests client.GetRawTransaction - used in withdraw_strategy_test.go
func TestRPC_GetRawTransaction(t *testing.T) {
	client := getTestClient(t)

	txID := getEnvOrSkip(t, "BTC_RPC_TXID")
	txHash, err := chainhash.NewHashFromStr(txID)
	require.NoError(t, err)

	tx, err := client.GetRawTransaction(txHash)
	require.NoError(t, err)
	require.NotNil(t, tx)
	assert.Equal(t, txID, tx.Hash().String())
}

// TestRPC_GetMempoolEntry tests client.GetMempoolEntry - used in withdraw_broadcast.go
func TestRPC_GetMempoolEntry(t *testing.T) {
	client := getTestClient(t)

	txID := getEnvOrSkip(t, "BTC_RPC_MEMPOOL_TXID")
	entry, err := client.GetMempoolEntry(txID)
	require.NoError(t, err)
	require.NotNil(t, entry)
}

// TestRPC_EstimateSmartFee tests client.EstimateSmartFee - used in fee.go
func TestRPC_EstimateSmartFee(t *testing.T) {
	client := getTestClient(t)

	if os.Getenv("BTC_RPC_ENABLE_ESTIMATE_FEE") == "" {
		t.Skip("Skipping: BTC_RPC_ENABLE_ESTIMATE_FEE not set")
	}

	feeEstimate, err := client.EstimateSmartFee(1, &btcjson.EstimateModeConservative)
	require.NoError(t, err)
	require.NotNil(t, feeEstimate)
	require.NotNil(t, feeEstimate.FeeRate)
}

// TestRPC_SendRawTransaction tests client.SendRawTransaction error handling - used in withdraw_broadcast.go
func TestRPC_RawRequest_SendRawTransaction(t *testing.T) {
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

func TestRPC_SendRawTransaction(t *testing.T) {
	client := getTestClient(t)

	invalidTx := &wire.MsgTx{}
	_, err := client.SendRawTransaction(invalidTx, false)
	require.Error(t, err)
}

// TestRPCService_GetBlockTimeFromTx tests BTCRPCService.GetBlockTimeFromTx - used in consensus_event.go
func TestRPCService_GetBlockTimeFromTx(t *testing.T) {
	client := getTestClient(t)
	service := NewBTCRPCService(client)

	txID := getEnvOrSkip(t, "BTC_RPC_TXID")
	txHash, err := chainhash.NewHashFromStr(txID)
	require.NoError(t, err)

	blockTime, err := service.GetBlockTimeFromTx(*txHash)
	require.NoError(t, err)
	assert.Greater(t, blockTime, int64(0))
}

// TestRPCService_GetTxHashes tests BTCRPCService.GetTxHashes - used in consensus_event.go
func TestRPCService_GetTxHashes(t *testing.T) {
	client := getTestClient(t)
	service := NewBTCRPCService(client)

	blockHash := getEnvOrSkip(t, "BTC_RPC_BLOCK_HASH")
	parsedHash, err := chainhash.NewHashFromStr(blockHash)
	require.NoError(t, err)

	txHashes, err := service.GetTxHashes(parsedHash)
	require.NoError(t, err)
	require.NotEmpty(t, txHashes)
}

// TestRPCService_GetBlockData tests BTCRPCService.GetBlockData - used in withdraw_finalize.go
func TestRPCService_GetBlockData(t *testing.T) {
	client := getTestClient(t)
	service := NewBTCRPCService(client)

	testHeight := getEnvInt64OrSkip(t, "BTC_RPC_HEIGHT")

	blockData, err := service.GetBlockData(uint64(testHeight))
	require.NoError(t, err)
	require.NotNil(t, blockData)
	assert.Equal(t, uint64(testHeight), blockData.BlockHeight)
	assert.NotEmpty(t, blockData.BlockHash)
	assert.NotEmpty(t, blockData.Header)
	assert.NotEmpty(t, blockData.MerkleRoot)
	assert.Greater(t, blockData.BlockTime, int64(0))
	assert.NotEmpty(t, blockData.TxHashes)

	t.Logf("Block %d data: hash=%s, merkleRoot=%s, time=%d, difficulty=%d",
		blockData.BlockHeight, blockData.BlockHash, blockData.MerkleRoot, blockData.BlockTime, blockData.Difficulty)
}

// TestRPCService_GetBlockDataByHash tests BTCRPCService.GetBlockDataByHash - used in deposit.go
func TestRPCService_GetBlockDataByHash(t *testing.T) {
	client := getTestClient(t)
	service := NewBTCRPCService(client)

	blockHash := getEnvOrSkip(t, "BTC_RPC_BLOCK_HASH")
	testHeight := getEnvInt64OrSkip(t, "BTC_RPC_HEIGHT")

	blockData, err := service.GetBlockDataByHash(blockHash)
	require.NoError(t, err)
	require.NotNil(t, blockData)
	assert.Equal(t, uint64(testHeight), blockData.BlockHeight)
	assert.Equal(t, blockHash, blockData.BlockHash)
	assert.NotEmpty(t, blockData.Header)
	assert.NotEmpty(t, blockData.MerkleRoot)
	assert.Greater(t, blockData.BlockTime, int64(0))
	assert.NotEmpty(t, blockData.TxHashes)

	t.Logf("Block %s data: height=%d, merkleRoot=%s, time=%d, difficulty=%d",
		blockData.BlockHash, blockData.BlockHeight, blockData.MerkleRoot, blockData.BlockTime, blockData.Difficulty)
}

// TestRPCService_GetBlockHeader tests BTCRPCService.GetBlockHeader - for completeness
func TestRPCService_GetBlockHeader(t *testing.T) {
	client := getTestClient(t)
	service := NewBTCRPCService(client)

	blockHash := getEnvOrSkip(t, "BTC_RPC_BLOCK_HASH")
	parsedHash, err := chainhash.NewHashFromStr(blockHash)
	require.NoError(t, err)

	header, err := service.GetBlockHeader(parsedHash)
	require.NoError(t, err)
	require.NotNil(t, header)
	assert.Greater(t, header.Version, int32(0))
	assert.NotEmpty(t, header.PrevBlock.String())
	assert.NotEmpty(t, header.MerkleRoot.String())
	assert.Greater(t, header.Timestamp.Unix(), int64(0))

	t.Logf("Block %s header: version=%d, prevBlock=%s, merkleRoot=%s, time=%d",
		blockHash, header.Version, header.PrevBlock.String(), header.MerkleRoot.String(), header.Timestamp.Unix())
}
