package btc

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/types"
	"gorm.io/gorm"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/config"
	log "github.com/sirupsen/logrus"
)

type BTCNotifier struct {
	client         *rpcclient.Client
	confirmations  int64
	currentHeight  uint64
	bestHeight     int64
	catchingStatus bool
	catchingMu     sync.Mutex
	syncStatus     *db.BtcSyncStatus
	syncMu         sync.Mutex

	cache      *BTCCache
	poller     *BTCPoller
	feeFetcher NetworkFeeFetcher
}

func NewBTCNotifier(client *rpcclient.Client, cache *BTCCache, poller *BTCPoller) *BTCNotifier {
	var maxBlockHeight int64 = -1
	var lastBlock db.BtcBlockData
	result := cache.db.Order("block_height desc").First(&lastBlock)
	if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
		log.Fatalf("Failed to get max block height from db, %v", result.Error)
	}
	if result.Error == nil {
		maxBlockHeight = int64(lastBlock.BlockHeight) - 1
	}

	if maxBlockHeight < int64(config.AppConfig.BTCStartHeight) {
		maxBlockHeight = int64(config.AppConfig.BTCStartHeight) - 1
	}
	log.Infof("New btc notify at max block height is %d", maxBlockHeight)

	var syncStatus db.BtcSyncStatus
	resultQuery := cache.db.First(&syncStatus)
	if resultQuery.Error != nil && resultQuery.Error == gorm.ErrRecordNotFound {
		syncStatus.ConfirmedHeight = int64(config.AppConfig.BTCStartHeight - 1)
		syncStatus.UnconfirmHeight = int64(config.AppConfig.BTCStartHeight - 1)
		syncStatus.UpdatedAt = time.Now()
		cache.db.Create(&syncStatus)
		log.Info("New btc notify sync status not found, create one")
	} else if resultQuery.Error == nil {
		// check btc light db latest block
		confirmedBlock, err := poller.state.GetLatestConfirmedBtcBlock()
		if err != nil {
			log.Warnf("New btc notify sync status GetLatestConfirmedBtcBlock error: %v", err)
		}
		if confirmedBlock != nil && confirmedBlock.Height < uint64(syncStatus.ConfirmedHeight) {
			syncStatus.ConfirmedHeight = int64(confirmedBlock.Height)
			syncStatus.UpdatedAt = time.Now()
			log.Warnf("New btc notify sync status set confirmed height to %d", confirmedBlock.Height)
		}
	}
	log.Infof("New btc notify sync status confirmed height is %d", syncStatus.ConfirmedHeight)

	return &BTCNotifier{
		client:         client,
		confirmations:  int64(config.AppConfig.BTCConfirmations),
		currentHeight:  uint64(maxBlockHeight + 1),
		catchingStatus: true,
		syncStatus:     &syncStatus,
		cache:          cache,
		poller:         poller,
		feeFetcher:     NewMemPoolFeeFetcher(client),
	}
}

func (bn *BTCNotifier) Start(ctx context.Context) {
	bn.cache.Start(ctx)
	go bn.poller.Start(ctx)
	go bn.checkConfirmations(ctx)
}

func (bn *BTCNotifier) checkConfirmations(ctx context.Context) {
	checkInterval := 30 * time.Second
	catchUpInterval := 1 * time.Second
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
				log.Errorf("Error getting latest block height: %v", err)
				continue
			}

			if bestHeight <= bn.bestHeight {
				// no need to sync
				log.Debugf("No need to sync, remote best height: %d, local best height: %d", bestHeight, bn.bestHeight)
				continue
			}
			defer func() {
				bn.bestHeight = bestHeight
			}()

			bn.updateCatchingStatus(bestHeight)

			confirmedHeight := bestHeight - bn.confirmations
			log.Debugf("BTC block confirmation: best height=%d, confirmed height=%d, current height=%d", bestHeight, confirmedHeight, bn.currentHeight)

			bn.syncMu.Lock()
			syncConfirmedHeight := bn.syncStatus.ConfirmedHeight
			bn.syncMu.Unlock()

			if syncConfirmedHeight >= confirmedHeight {
				bn.handleDepositResults()
				bn.poller.state.UpdateBtcSyncing(false)
				log.Debugf("No need to sync, best height: %d, confirmed height: %d", bestHeight, confirmedHeight)
				continue
			}

			bn.poller.state.UpdateBtcSyncing(true)
			err = bn.updateNetworkFee()
			if err != nil {
				log.Errorf("Failed to update network fee at best height: %d, error: %v", bestHeight, err)
				break
			}

			newSyncHeight := syncConfirmedHeight
			log.Infof("BTC sync started: best height=%d, from=%d, to=%d", bestHeight, syncConfirmedHeight+1, confirmedHeight)

			for height := syncConfirmedHeight + 1; height <= confirmedHeight; height++ {
				if err := bn.processBlockAtHeight(height); err != nil {
					break
				}
				newSyncHeight = height
				bn.currentHeight++
				time.Sleep(catchUpInterval)
			}

			if syncConfirmedHeight != newSyncHeight {
				bn.saveSyncStatus(newSyncHeight, confirmedHeight)
			}
		}
	}
}

// update catching status
func (bn *BTCNotifier) updateCatchingStatus(bestHeight int64) {
	catchingStatus := int64(bn.currentHeight)+bn.confirmations < bestHeight
	bn.catchingMu.Lock()
	bn.catchingStatus = catchingStatus
	bn.catchingMu.Unlock()
}

// handle deposit results need fetch sub script
func (bn *BTCNotifier) handleDepositResults() {
	depositResults, err := bn.poller.state.GetDepositResultsNeedFetchSubScript()
	if err != nil {
		log.Errorf("Error fetching deposit results: %v", err)
		return
	}

	for _, depositResult := range depositResults {
		bn.fetchSubScriptForDeposit(depositResult)
	}
}

// update network fee
func (bn *BTCNotifier) updateNetworkFee() error {
	// check network fee from api first, if failed, get fee from btc node
	fee, err := bn.feeFetcher.GetNetworkFee()
	if err != nil {
		log.Errorf("Failed to get network fee from fee fetcher: %v", err)
		return err
	}

	log.Infof("BTC network fee (sat/vbyte): %+v", fee)
	bn.poller.state.UpdateBtcNetworkFee(fee.FastestFee, fee.HalfHourFee, fee.HourFee)
	return nil
}

// process block at height
func (bn *BTCNotifier) processBlockAtHeight(height int64) error {
	block, err := bn.getBlockAtHeight(height)
	if err != nil {
		log.Errorf("Error fetching block at height %d: %v", height, err)
		return err
	}
	bn.cache.blockChan <- BlockWithHeight{Block: block, Height: uint64(height)}
	bn.poller.confirmChan <- &types.BtcBlockExt{MsgBlock: *block, BlockNumber: uint64(height)}
	return nil
}

// save sync status
func (bn *BTCNotifier) saveSyncStatus(newSyncHeight, confirmedHeight int64) {
	bn.syncMu.Lock()
	defer bn.syncMu.Unlock()

	bn.syncStatus.ConfirmedHeight = newSyncHeight
	bn.syncStatus.UpdatedAt = time.Now()
	bn.cache.db.Save(bn.syncStatus)

	if newSyncHeight >= confirmedHeight {
		bn.poller.state.UpdateBtcSyncing(false)
	}
}

func (bn *BTCNotifier) fetchSubScriptForDeposit(depositResult *db.DepositResult) {
	log.Debugf("Processing deposit result: Txid=%s, TxOut=%d, Address=%s", depositResult.Txid, depositResult.TxOut, depositResult.Address)

	txHash, err := chainhash.NewHashFromStr(depositResult.Txid)
	if err != nil {
		log.Errorf("Failed to create chain hash from string %s, error: %v", depositResult.Txid, err)
		return
	}

	tx, err := bn.client.GetRawTransactionVerbose(txHash)
	if err != nil {
		log.Errorf("Failed to fetch transaction details for Txid: %s, error: %v", depositResult.Txid, err)
		return
	}

	if len(tx.Vout) > int(depositResult.TxOut) {
		blockHash, _ := chainhash.NewHashFromStr(tx.BlockHash)
		// get deposit key by btc block height
		block, err := bn.client.GetBlockVerbose(blockHash)
		if err != nil {
			log.Errorf("Failed to get block details for Txid: %s, error: %v", depositResult.Txid, err)
			return
		}
		pubkey, err := bn.poller.state.GetDepositKeyByBtcBlock(uint64(block.Height))
		if err != nil {
			log.Errorf("Failed to get deposit key for BTC block at height %d, error: %v", block.Height, err)
			return
		}

		pubkeyBytes, err := base64.StdEncoding.DecodeString(pubkey.PubKey)
		if err != nil {
			log.Errorf("Failed to decode pubkey %s, error: %v", pubkey.PubKey, err)
			return
		}

		// update utxo sub script
		err = bn.poller.state.UpdateUtxoSubScript(depositResult.Txid, depositResult.TxOut, depositResult.Address, pubkeyBytes)
		if err != nil && err != gorm.ErrRecordNotFound {
			log.Errorf("Failed to update UTXO sub script for Txid %s, error: %v", depositResult.Txid, err)
			return
		}

		if err == gorm.ErrRecordNotFound {
			// handle p2wsh deposit
			bn.handleP2WSHDeposit(tx, block.Height, depositResult, pubkeyBytes)
		}

	} else {
		log.Errorf("Transaction Vout length does not match for Txid: %s, expected output index: %d, got Vout length: %d",
			depositResult.Txid, depositResult.TxOut+1, len(tx.Vout))
	}
}

func (bn *BTCNotifier) handleP2WSHDeposit(tx *btcjson.TxRawResult, blockHeight int64, depositResult *db.DepositResult, pubkeyBytes []byte) {
	log.Infof("Processing P2WSH deposit for Txid: %s, TxOut: %d", depositResult.Txid, depositResult.TxOut)

	// get network type
	net := types.GetBTCNetwork(config.AppConfig.BTCNetworkType)

	// generate p2wsh address
	p2wsh, err := types.GenerateV0P2WSHAddress(pubkeyBytes, depositResult.Address, net)
	if err != nil {
		log.Errorf("Failed to generate P2WSH address for Txid: %s, error: %v", depositResult.Txid, err)
		return
	}

	// check utxo is v0 deposit
	isV0, outputIndex, amount, pkScript := types.IsUtxoGoatDepositV0Json(tx, []btcutil.Address{p2wsh}, net)
	if !isV0 || outputIndex != int(depositResult.TxOut) {
		log.Warnf("UTXO is not a valid V0 deposit or output index mismatch for Txid: %s, TxOut: %d", depositResult.Txid, depositResult.TxOut)
		return
	}

	log.Infof("Valid P2WSH deposit found for Txid: %s, TxOut: %d", depositResult.Txid, depositResult.TxOut)

	// create new utxo
	utxo := &db.Utxo{
		Txid:          tx.Txid,
		PkScript:      pkScript,
		OutIndex:      outputIndex,
		Amount:        amount,
		Receiver:      p2wsh.EncodeAddress(),
		WalletVersion: "1",
		EvmAddr:       depositResult.Address,
		Source:        db.UTXO_SOURCE_DEPOSIT,
		ReceiverType:  db.WALLET_TYPE_P2WSH,
		Status:        db.UTXO_STATUS_PROCESSED,
		ReceiveBlock:  uint64(blockHeight),
		SpentBlock:    0,
		UpdatedAt:     time.Now(),
	}

	// save utxo to db
	err = bn.poller.state.AddUtxo(utxo, nil, "", 0, nil, nil, nil, 0, true)
	if err != nil {
		log.Errorf("Failed to save UTXO for Txid: %s, error: %v", depositResult.Txid, err)
	}
}

func (bn *BTCNotifier) getBlockAtHeight(height int64) (*wire.MsgBlock, error) {
	blockHash, err := bn.client.GetBlockHash(height)
	if err != nil {
		return nil, fmt.Errorf("error getting block hash at height %d: %v", height, err)
	}

	block, err := bn.client.GetBlock(blockHash)
	if err != nil {
		return nil, fmt.Errorf("error getting block at height %d: %v", height, err)
	}

	return block, nil
}
