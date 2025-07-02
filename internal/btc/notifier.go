package btc

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
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
	reindexBlocks  []string
	bestHeight     int64
	catchingStatus bool
	catchingMu     sync.Mutex
	syncStatus     *db.BtcSyncStatus
	syncMu         sync.Mutex
	initOnce       sync.Once

	poller     *BTCPoller
	feeFetcher NetworkFeeFetcher
}

func NewBTCNotifier(client *rpcclient.Client, poller *BTCPoller) *BTCNotifier {
	var maxBlockHeight int64 = -1
	var reindexBlocks []string

	// No longer retrieve the maximum block height from the cache database, switch to getting it from RPC
	blockCount, err := client.GetBlockCount()
	if err != nil {
		log.Fatalf("Failed to get block count from RPC, %v", err)
	}
	maxBlockHeight = blockCount - 1

	if maxBlockHeight < int64(config.AppConfig.BTCStartHeight) {
		maxBlockHeight = int64(config.AppConfig.BTCStartHeight) - 1
	}
	log.Infof("New btc notify at max block height is %d", maxBlockHeight)

	if config.AppConfig.BTCReindexBlocks != "" {
		reindexBlocks = strings.Split(config.AppConfig.BTCReindexBlocks, ",")
		log.Infof("New btc notify reindex blocks are %v", reindexBlocks)
	}

	var syncStatus *db.BtcSyncStatus
	resultQuery, err := poller.state.GetBtcSyncStatus()
	if err != nil && err == gorm.ErrRecordNotFound {
		syncStatus, err = poller.state.CreateBtcSyncStatus(int64(config.AppConfig.BTCStartHeight-1), int64(config.AppConfig.BTCStartHeight-1))
		if err != nil {
			log.Errorf("New btc notify failed to create sync status: %v", err)
		}
		log.Info("New btc notify sync status not found, create one")
	} else if err == nil {
		syncStatus = resultQuery
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

	confirmedBlock, err := poller.state.GetLatestConfirmedBtcBlock()
	if err != nil {
		log.Warnf("New btc notify sync status GetLatestConfirmedBtcBlock error: %v", err)
	}
	if confirmedBlock != nil && confirmedBlock.Height < uint64(syncStatus.ConfirmedHeight) {
		syncStatus.ConfirmedHeight = int64(confirmedBlock.Height)
		syncStatus.UpdatedAt = time.Now()
		log.Warnf("New btc notify sync status set confirmed height to %d", confirmedBlock.Height)
	}

	log.Infof("New btc notify sync status confirmed height is %d", syncStatus.ConfirmedHeight)

	return &BTCNotifier{
		client:         client,
		confirmations:  int64(config.AppConfig.BTCConfirmations),
		currentHeight:  uint64(maxBlockHeight + 1),
		reindexBlocks:  reindexBlocks,
		catchingStatus: true,
		syncStatus:     syncStatus,
		poller:         poller,
		feeFetcher:     NewMemPoolFeeFetcher(client),
	}
}

func (bn *BTCNotifier) Start(ctx context.Context, blockDoneCh chan struct{}) {
	go bn.poller.Start(ctx)
	go bn.checkConfirmations(ctx, blockDoneCh)
}

func (bn *BTCNotifier) checkConfirmations(ctx context.Context, blockDoneCh chan struct{}) {
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

			err = bn.updateNetworkFee()
			if err != nil {
				log.Errorf("Failed to update network fee at best height: %d, error: %v", bestHeight, err)
				continue
			}

			bn.initOnce.Do(func() {
				for len(bn.reindexBlocks) > 0 {
					height := bn.reindexBlocks[0]
					log.Infof("Reindex block: %s", height)
					heightInt, err := strconv.ParseInt(height, 10, 64)
					if err != nil {
						log.Warnf("Failed to parse reindex block: %s, error: %v", height, err)
						break
					}
					if heightInt > bestHeight {
						log.Warnf("Reindex block height is larger than best height %d, skip", bestHeight)
						break
					}
					if err := bn.processBlockAtHeight(heightInt, blockDoneCh); err != nil {
						break
					}
					time.Sleep(catchUpInterval)
					// remove the processed block
					bn.reindexBlocks = bn.reindexBlocks[1:]
				}
			})

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

			newSyncHeight := syncConfirmedHeight
			log.Infof("BTC sync started: best height=%d, from=%d, to=%d", bestHeight, syncConfirmedHeight+1, confirmedHeight)

			for height := syncConfirmedHeight + 1; height <= confirmedHeight; height++ {
				if err := bn.processBlockAtHeight(height, blockDoneCh); err != nil {
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

		// Use default values when fee fetching fails completely
		defaultFee := &types.BtcNetworkFee{
			FastestFee:  3,
			HalfHourFee: 3,
			HourFee:     3,
		}

		log.Warnf("Using default network fee values: %+v", defaultFee)
		bn.poller.state.UpdateBtcNetworkFee(defaultFee.FastestFee, defaultFee.HalfHourFee, defaultFee.HourFee)
		return nil // Return nil to prevent error propagation
	}

	log.Infof("BTC network fee (sat/vbyte): %+v", fee)
	bn.poller.state.UpdateBtcNetworkFee(fee.FastestFee, fee.HalfHourFee, fee.HourFee)
	return nil
}

// process block at height
func (bn *BTCNotifier) processBlockAtHeight(height int64, blockDoneCh chan struct{}) error {
	block, err := bn.getBlockAtHeight(height)
	if err != nil {
		log.Errorf("Error fetching block at height %d: %v", height, err)
		return err
	}
	bn.poller.confirmChan <- &types.BtcBlockExt{MsgBlock: *block, BlockNumber: uint64(height)}

	<-blockDoneCh
	log.Infof("Confirmed block %d fully processed", height)
	return nil
}

// save sync status
func (bn *BTCNotifier) saveSyncStatus(newSyncHeight, confirmedHeight int64) {
	bn.syncMu.Lock()
	defer bn.syncMu.Unlock()

	bn.syncStatus.ConfirmedHeight = newSyncHeight
	bn.syncStatus.UpdatedAt = time.Now()

	err := bn.poller.state.SaveBtcSyncStatus(bn.syncStatus)
	if err != nil {
		log.Errorf("Failed to save sync status: %v", err)
	}

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

	tx, err := bn.poller.rpcService.GetRawTransactionVerbose(txHash)
	if err != nil {
		log.Errorf("Failed to fetch transaction details for Txid: %s, error: %v", depositResult.Txid, err)
		return
	}

	if len(tx.Vout) > int(depositResult.TxOut) {
		blockHash, _ := chainhash.NewHashFromStr(tx.BlockHash)
		// get deposit key by btc block height
		block, err := bn.poller.rpcService.GetBlockVerbose(blockHash)
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
