package btc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/goatnetwork/goat-relayer/internal/types"
	"gorm.io/gorm"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

type BtcBlockExt struct {
	*chainhash.Hash
	blockNumber uint64
}

type BTCPoller struct {
	db          *gorm.DB
	state       *state.State
	confirmChan chan *BtcBlockExt
}

func NewBTCPoller(state *state.State, db *gorm.DB) *BTCPoller {
	return &BTCPoller{
		state:       state,
		db:          db,
		confirmChan: make(chan *BtcBlockExt),
	}
}

func (p *BTCPoller) Start(ctx context.Context) {
	go p.pollLoop(ctx)
}

func (p *BTCPoller) Stop() {
}

func (p *BTCPoller) pollLoop(ctx context.Context) {
	for {
		select {
		case blockHash := <-p.confirmChan:
			p.handleConfirmedBlock(blockHash)
		case <-ctx.Done():
			log.Info("Stopping the polling of confirmed blocks...")
			return
		}
	}
}

func (p *BTCPoller) GetBlockHashForTx(txHash chainhash.Hash) (*chainhash.Hash, error) {
	var btcTxOutput db.BtcTXOutput

	if err := p.db.Where("tx_hash = ?", txHash.String()).First(&btcTxOutput).Error; err != nil {
		return nil, fmt.Errorf("failed to find the block hash for the transaction: %v", err)
	}

	blockHashBytes := btcTxOutput.PkScript[:32] // Assuming the block hash is the first 32 bytes of PkScript
	blockHash, err := chainhash.NewHash(blockHashBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create hash from block hash bytes: %v", err)
	}

	return blockHash, nil
}
func (p *BTCPoller) GetBlockHeader(blockHash *chainhash.Hash) (*wire.BlockHeader, error) {
	var blockData db.BtcBlockData
	if err := p.db.Where("block_hash = ?", blockHash.String()).First(&blockData).Error; err != nil {
		return nil, fmt.Errorf("failed to retrieve block header from database: %v", err)
	}

	header := wire.BlockHeader{}
	err := header.Deserialize(bytes.NewReader([]byte(blockData.Header)))
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize block header: %v", err)
	}

	return &header, nil
}

func (p *BTCPoller) GetTxHashes(blockHash *chainhash.Hash) ([]chainhash.Hash, error) {
	var txHashes []chainhash.Hash

	var blockData db.BtcBlockData
	if err := p.db.Where("block_hash = ?", blockHash.String()).First(&blockData).Error; err != nil {
		return nil, fmt.Errorf("failed to retrieve block data from database: %v", err)
	}

	err := json.Unmarshal([]byte(blockData.TxHashes), &txHashes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal transaction hash list: %v", err)
	}

	return txHashes, nil
}

func (p *BTCPoller) GetBlock(height uint64) (*wire.MsgBlock, error) {
	var blockData db.BtcBlockData
	if err := p.db.Where("block_height = ?", height).First(&blockData).Error; err != nil {
		return nil, fmt.Errorf("error retrieving block from database: %v", err)
	}

	block := wire.MsgBlock{}
	err := block.Header.Deserialize(bytes.NewReader([]byte(blockData.Header)))
	if err != nil {
		return nil, fmt.Errorf("error deserializing block: %v", err)
	}

	return &block, nil
}

func (p *BTCPoller) GetBlockHash(height uint64) (*chainhash.Hash, error) {
	var blockData db.BtcBlockData
	if err := p.db.Where("block_height = ?", height).First(&blockData).Error; err != nil {
		return nil, fmt.Errorf("error retrieving block from database: %v", err)
	}

	hashBytes, err := hex.DecodeString(blockData.BlockHash)
	if err != nil {
		return nil, fmt.Errorf("error decoding block hash: %v", err)
	}

	blockHash, err := chainhash.NewHash(hashBytes)
	if err != nil {
		return nil, fmt.Errorf("error creating block hash: %v", err)
	}

	return blockHash, nil
}

func (p *BTCPoller) handleConfirmedBlock(block *BtcBlockExt) {
	// Logic for handling confirmed blocks
	blockHash := block.Hash
	log.Infof("Handling confirmed block: %d, hash:%s", block.blockNumber, blockHash.String())

	// TODO: it needs to use state to manange received block
	// then start sig one by one,
	// rules: state.GetL2Info().LatestBtcHeight+1, multiple block hash
	// TODO below is test 1 block
	if p.state.GetL2Info().LatestBtcHeight+1 == block.blockNumber {
		epochVoter := p.state.GetEpochVoter()
		p.state.EventBus.Publish(state.SigStart, types.MsgSignNewBlock{
			MsgSign: types.MsgSign{
				RequestId:    fmt.Sprintf("BTCHEAD:%d", block.blockNumber),
				Sequence:     epochVoter.Seqeuence,
				Epoch:        epochVoter.Epoch,
				IsProposer:   true,
				VoterAddress: epochVoter.Proposer,
				SigData:      nil,
				CreateTime:   time.Now().Unix(),
			},
			StartBlockNumber: block.blockNumber,
			BlockHash:        [][]byte{blockHash.CloneBytes()},
		})
	}
}
