package btc

import (
	"context"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/goatnetwork/goat-relayer/internal/config"
	log "github.com/sirupsen/logrus"
)

type BTCNotifier struct {
	client        *rpcclient.Client
	currentHeight uint64

	cache  *BTCCache
	poller *BTCPoller
}

func NewBTCNotifier(client *rpcclient.Client, cache *BTCCache, poller *BTCPoller) *BTCNotifier {
	var maxBlockHeight uint64 = 0
	result := cache.db.Model(&db.BtcBlockData{}).Select("MAX(block_height)").Row()
	result.Scan(&maxBlockHeight)
	if maxBlockHeight < uint64(config.AppConfig.BTCStartHeight) {
		maxBlockHeight = uint64(config.AppConfig.BTCStartHeight)
	}

	return &BTCNotifier{
		client:        client,
		currentHeight: maxBlockHeight,
		cache:         cache,
		poller:        poller,
	}
}

func (bn *BTCNotifier) Start(ctx context.Context) {
	go bn.listenForBTCBlocks(ctx)
	go bn.checkConfirmations(ctx)
}

func (bn *BTCNotifier) listenForBTCBlocks(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping BTC block listening...")
			return
		default:
			time.Sleep(10 * time.Second)
			bn.currentHeight++

			bestHeight, err := bn.client.GetBlockCount()
			if err != nil {
				log.Printf("Error getting the latest block height: %v", err)
				continue
			}

			if int64(bn.currentHeight) > bestHeight {
				log.Printf("Reached the latest block, waiting for new blocks...")
				bn.currentHeight = uint64(bestHeight)
				continue
			}

			blockHash, err := bn.client.GetBlockHash(int64(bn.currentHeight))
			if err != nil {
				log.Printf("Error getting block hash: %v", err)
				continue
			}

			block, err := bn.client.GetBlock(blockHash)
			if err != nil {
				log.Printf("Error getting block: %v", err)
				continue
			}

			blockWithHeight := BlockWithHeight{
				Block:  block,
				Height: bn.currentHeight,
			}
			bn.cache.blockChan <- blockWithHeight
			log.Printf("Starting to cache block at height %d", bn.currentHeight)
		}
	}
}

func (bn *BTCNotifier) checkConfirmations(ctx context.Context) {
	checkInterval := 10 * time.Second
	requiredConfirmations := uint64(6) // Can be adjusted as needed

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping confirmation checks...")
			return
		case <-ticker.C:
			bestHeight, err := bn.client.GetBlockCount()
			if err != nil {
				log.Printf("Error getting the latest block height: %v", err)
				continue
			}

			confirmedHeight := uint64(bestHeight) - requiredConfirmations + 1
			for height := bn.currentHeight - requiredConfirmations; height <= confirmedHeight; height++ {
				blockHash, err := bn.poller.GetBlockHash(height)
				if err != nil {
					log.Printf("Error getting block at height %d from cache: %v", height, err)
					continue
				}

				bn.poller.confirmChan <- &BtcBlockExt{
					Hash:        blockHash,
					blockNumber: height,
				}
				log.Infof("Starting to submit block hash at height %d to consensus", height)
			}
		}
	}
}
