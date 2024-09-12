package btc

import (
	"bytes"
	"context"
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
	wire.MsgBlock

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
		confirmChan: make(chan *BtcBlockExt, 64),
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
		case block := <-p.confirmChan:
			p.handleConfirmedBlock(block)
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

func (p *BTCPoller) GetBlock(height uint64) (*db.BtcBlockData, error) {
	var blockData db.BtcBlockData
	if err := p.db.Where("block_height = ?", height).First(&blockData).Error; err != nil {
		return nil, fmt.Errorf("error retrieving block from database: %v", err)
	}
	return &blockData, nil
}

func (p *BTCPoller) handleConfirmedBlock(block *BtcBlockExt) {
	// Logic for handling confirmed blocks
	blockHash := block.BlockHash()
	log.Infof("Handling confirmed block: %d, hash:%s", block.blockNumber, blockHash.String())

	// it use state to manange received block
	// then start sig one by one,
	p.state.UpdateSigBtcBlock(&db.BtcBlock{
		Height: block.blockNumber,
		Hash:   blockHash.String(),
		Status: "pending",
	}, block.blockNumber, blockHash.String())

	// rules: state.GetL2Info().LatestBtcHeight+1, multiple block hash
	log.Infof("Publish to SigStart bus, block: %d, hash:%s", block.blockNumber, blockHash.String())
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
