package btc

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/db"
	log "github.com/sirupsen/logrus"
)

// BTCRPCService provides functionality to query Bitcoin data directly via RPC
type BTCRPCService struct {
	client *rpcclient.Client
}

// NewBTCRPCService creates a new instance of the RPC service
func NewBTCRPCService(client *rpcclient.Client) *BTCRPCService {
	return &BTCRPCService{
		client: client,
	}
}

// GetBlockData retrieves block data via RPC
func (s *BTCRPCService) GetBlockData(height uint64) (*db.BtcBlockData, error) {
	// Get block hash by height
	blockHash, err := s.client.GetBlockHash(int64(height))
	if err != nil {
		return nil, fmt.Errorf("failed to get block hash at height %d: %v", height, err)
	}

	// Get block
	block, err := s.client.GetBlock(blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get block at height %d: %v", height, err)
	}

	return s.convertBlockToBlockData(block, height)
}

// GetBlockDataByHash retrieves block data by block hash
func (s *BTCRPCService) GetBlockDataByHash(blockHashStr string) (*db.BtcBlockData, error) {
	blockHash, err := chainhash.NewHashFromStr(blockHashStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block hash %s: %v", blockHashStr, err)
	}

	// Get block
	block, err := s.client.GetBlock(blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get block with hash %s: %v", blockHashStr, err)
	}

	// Get block height
	blockVerbose, err := s.client.GetBlockVerbose(blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get block verbose with hash %s: %v", blockHashStr, err)
	}

	return s.convertBlockToBlockData(block, uint64(blockVerbose.Height))
}

// GetBlockHeader retrieves the block header by block hash
func (s *BTCRPCService) GetBlockHeader(blockHash *chainhash.Hash) (*wire.BlockHeader, error) {
	// Get block
	block, err := s.client.GetBlock(blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get block header: %v", err)
	}

	return &block.Header, nil
}

// GetTxHashes retrieves the list of transaction hashes by block hash
func (s *BTCRPCService) GetTxHashes(blockHash *chainhash.Hash) ([]chainhash.Hash, error) {
	// Get block
	block, err := s.client.GetBlock(blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get block: %v", err)
	}

	// Get transaction hashes
	txHashes, err := block.TxHashes()
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction hashes: %v", err)
	}

	return txHashes, nil
}

// GetBlockHashForTx retrieves the block hash by transaction hash
func (s *BTCRPCService) GetBlockHashForTx(txHash chainhash.Hash) (*chainhash.Hash, error) {
	txRawResult, err := s.client.GetRawTransactionVerbose(&txHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get raw transaction: %v", err)
	}

	if txRawResult.BlockHash == "" {
		return nil, fmt.Errorf("transaction not in any block")
	}

	blockHash, err := chainhash.NewHashFromStr(txRawResult.BlockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block hash: %v", err)
	}

	return blockHash, nil
}

// GetBlockTimeFromTx retrieves the block time from transaction hash
func (s *BTCRPCService) GetBlockTimeFromTx(txHash chainhash.Hash) (blockTime int64, err error) {
	txRawResult, err := s.client.GetRawTransactionVerbose(&txHash)
	if err != nil {
		return 0, fmt.Errorf("failed to get raw transaction: %v", err)
	}
	return txRawResult.Blocktime, nil
}

// GetRawTransactionVerbose retrieves detailed information of a transaction
func (s *BTCRPCService) GetRawTransactionVerbose(txHash *chainhash.Hash) (*btcjson.TxRawResult, error) {
	return s.client.GetRawTransactionVerbose(txHash)
}

// GetBlockVerbose retrieves detailed information of a block
func (s *BTCRPCService) GetBlockVerbose(blockHash *chainhash.Hash) (*btcjson.GetBlockVerboseResult, error) {
	return s.client.GetBlockVerbose(blockHash)
}

// GetBlockVerboseTx retrieves detailed information of a block (including transactions)
func (s *BTCRPCService) GetBlockVerboseTx(blockHash *chainhash.Hash) (*btcjson.GetBlockVerboseTxResult, error) {
	return s.client.GetBlockVerboseTx(blockHash)
}

// convertBlockToBlockData converts wire.MsgBlock to db.BtcBlockData
func (s *BTCRPCService) convertBlockToBlockData(block *wire.MsgBlock, height uint64) (*db.BtcBlockData, error) {
	blockHash := block.BlockHash().String()
	header := block.Header
	difficulty := header.Bits
	randomNumber := header.Nonce
	merkleRoot := header.MerkleRoot.String()
	blockTime := header.Timestamp.Unix()

	// Serialize block header
	headerBuffer := new(bytes.Buffer)
	err := header.Serialize(headerBuffer)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize block header: %v", err)
	}
	headerBytes := headerBuffer.Bytes()

	// Get transaction hashes
	txHashes, err := block.TxHashes()
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction hashes: %v", err)
	}
	txHashesJSON, err := json.Marshal(txHashes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction hashes: %v", err)
	}

	blockData := &db.BtcBlockData{
		BlockHeight:  height,
		BlockHash:    blockHash,
		Header:       headerBytes,
		Difficulty:   difficulty,
		RandomNumber: randomNumber,
		MerkleRoot:   merkleRoot,
		BlockTime:    blockTime,
		TxHashes:     string(txHashesJSON),
	}

	log.Debugf("RPC fetched block %s data: header %x, difficulty %d, random number %d, Merkle root %s, block time %d",
		blockHash, headerBytes, difficulty, randomNumber, merkleRoot, blockTime)

	return blockData, nil
}
