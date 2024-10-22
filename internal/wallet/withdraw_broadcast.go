package wallet

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/http"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/goatnetwork/goat-relayer/internal/types"
	log "github.com/sirupsen/logrus"
)

type OrderBroadcaster interface {
	Start(ctx context.Context)
	Stop()
	broadcastOrders()
	broadcastPendingCheck()
}

type RemoteClient interface {
	SendRawTransaction(tx *wire.MsgTx, utxos []*db.Utxo, orderType string) (txHash string, exist bool, err error)
	CheckPending(txid string, externalTxId string, updatedAt time.Time) (revert bool, confirmations uint64, blockHeight uint64, err error)
}

type BtcClient struct {
	client *rpcclient.Client
}

type FireblocksClient struct {
	client *http.FireblocksProposal
}

type BaseOrderBroadcaster struct {
	remoteClient RemoteClient
	state        *state.State

	txBroadcastMu sync.Mutex
	// txBroadcastStatus          bool
	// txBroadcastFinishBtcHeight uint64
}

var (
	_ RemoteClient = (*BtcClient)(nil)
	_ RemoteClient = (*FireblocksClient)(nil)

	_ OrderBroadcaster = (*BaseOrderBroadcaster)(nil)
)

func (c *BtcClient) SendRawTransaction(tx *wire.MsgTx, utxos []*db.Utxo, orderType string) (txHash string, exist bool, err error) {
	txid := tx.TxHash().String()
	privKeyBytes, err := hex.DecodeString(config.AppConfig.FireblocksPrivKey)
	if err != nil {
		return txid, false, fmt.Errorf("decode privKey error: %v", err)
	}
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)
	// sign the transaction
	err = SignTransactionByPrivKey(privKey, tx, utxos, types.GetBTCNetwork(config.AppConfig.BTCNetworkType))
	if err != nil {
		return txid, false, fmt.Errorf("sign tx %s error: %v", txid, err)
	}
	_, err = c.client.SendRawTransaction(tx, false)
	if err != nil {
		if rpcErr, ok := err.(*btcjson.RPCError); ok {
			switch rpcErr.Code {
			case btcjson.ErrRPCTxAlreadyInChain:
				return txid, true, err
			}
		}
		return txid, false, err
	}
	return txid, false, nil
}

func (c *BtcClient) CheckPending(txid string, externalTxId string, updatedAt time.Time) (revert bool, confirmations uint64, blockHeight uint64, err error) {
	txHash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return false, 0, 0, fmt.Errorf("new hash from str error: %v, raw txid: %s", err, txid)
	}

	txRawResult, err := c.client.GetRawTransactionVerbose(txHash)
	if err != nil {
		return c.handleTxNotFoundError(err, txid, updatedAt)
	}

	blockHash, err := chainhash.NewHashFromStr(txRawResult.BlockHash)
	if err != nil {
		return false, 0, 0, fmt.Errorf("new hash from str error: %v, raw block hash: %s", err, txRawResult.BlockHash)
	}

	// query block
	block, err := c.client.GetBlockVerbose(blockHash)
	if err != nil {
		return false, 0, 0, fmt.Errorf("get block verbose error: %v, block hash: %s", err, blockHash.String())
	}

	// if found, return confirmations and block height
	return false, txRawResult.Confirmations, uint64(block.Height), nil
}

// handleTxNotFoundError handle tx not found error
func (c *BtcClient) handleTxNotFoundError(err error, txid string, updatedAt time.Time) (bool, uint64, uint64, error) {
	if rpcErr, ok := err.(*btcjson.RPCError); ok && rpcErr.Code == btcjson.ErrRPCNoTxInfo {
		timeDuration := time.Since(updatedAt)

		// if tx not found in 10 minutes to 20 minutes or over 72 hours, revert
		if c.shouldRevert(timeDuration) {
			return c.checkMempoolAndRevert(txid, timeDuration)
		}

		// if tx not found in 10 minutes to 20 minutes or over 72 hours, waiting
		log.Infof("Transaction not found yet, waiting for more time, txid: %s", txid)
		return false, 0, 0, nil
	}

	return false, 0, 0, fmt.Errorf("get raw transaction verbose error: %v, txid: %s", err, txid)
}

// shouldRevert check if revert is needed
func (c *BtcClient) shouldRevert(timeDuration time.Duration) bool {
	return (timeDuration >= 10*time.Minute && timeDuration <= 20*time.Minute) || timeDuration > 72*time.Hour
}

// checkMempoolAndRevert check mempool and revert
func (c *BtcClient) checkMempoolAndRevert(txid string, timeDuration time.Duration) (bool, uint64, uint64, error) {
	_, err := c.client.GetMempoolEntry(txid)
	if err == nil {
		// if tx in mempool, it is pending
		log.Infof("Transaction is still in mempool, waiting, txid: %s", txid)
		return false, 0, 0, nil
	}

	if rpcErr, ok := err.(*btcjson.RPCError); ok && rpcErr.Code == btcjson.ErrRPCClientMempoolDisabled {
		log.Warnf("Mempool is disabled, txid: %s", txid)
		// if mempool is disabled, and time less than 72 hours, record warning
		if timeDuration <= 72*time.Hour {
			return false, 0, 0, fmt.Errorf("mempool is disabled, txid: %s", txid)
		}
	}

	// if tx not found or mempool is disabled, revert
	log.Warnf("Transaction not found in %d minutes, reverting for re-submission, txid: %s", uint64(timeDuration.Minutes()), txid)
	return true, 0, 0, nil
}

func (c *FireblocksClient) SendRawTransaction(tx *wire.MsgTx, utxos []*db.Utxo, orderType string) (txHash string, exist bool, err error) {
	txid := tx.TxHash().String()
	rawMessage, err := GenerateRawMeessageToFireblocks(tx, utxos, types.GetBTCNetwork(config.AppConfig.BTCNetworkType))
	if err != nil {
		return txid, false, fmt.Errorf("generate raw message to fireblocks error: %v", err)
	}

	resp, err := c.client.PostRawSigningRequest(rawMessage, fmt.Sprintf("%s:%s", orderType, txid))
	if err != nil {
		return txid, false, fmt.Errorf("post raw signing request error: %v", err)
	}
	if resp.Code != 0 {
		return txid, false, fmt.Errorf("post raw signing request error: %v, txid: %s", resp.Message, txid)
	}
	log.Debugf("PostRawSigningRequest resp: %+v", resp)

	return resp.ID, false, nil
}

func (c *FireblocksClient) CheckPending(txid string, externalTxId string, updatedAt time.Time) (revert bool, confirmations uint64, blockHeight uint64, err error) {
	txDetails, err := c.client.QueryTransaction(externalTxId)
	if err != nil {
		return false, 0, 0, fmt.Errorf("get tx details from fireblocks error: %v, txid: %s", err, txid)
	}

	failedStatus := []string{"CANCELLING", "CANCELLED", "BLOCKED", "REJECTED", "FAILED"}
	// Check if txDetails.Status is in failedStatus
	for _, status := range failedStatus {
		if txDetails.Status == status {
			return true, 0, 0, nil
		}
	}

	blockHeight, err = strconv.ParseUint(txDetails.BlockInfo.BlockHeight, 10, 64)
	if err != nil {
		return false, 0, 0, fmt.Errorf("parse block height error: %v, txid: %s", err, txid)
	}

	return false, uint64(txDetails.NumOfConfirmations), blockHeight, nil
}

func NewOrderBroadcaster(btcClient *rpcclient.Client, state *state.State) OrderBroadcaster {
	orderBroadcaster := &BaseOrderBroadcaster{
		state: state,
	}
	if config.AppConfig.BTCNetworkType == "regtest" {
		orderBroadcaster.remoteClient = &BtcClient{
			client: btcClient,
		}
	} else {
		orderBroadcaster.remoteClient = &FireblocksClient{
			client: http.NewFireblocksProposal(),
		}
	}
	return orderBroadcaster
}

// txBroadcastLoop is a loop that broadcasts withdrawal and consolidation orders to the network
// check orders pending status, if it is failed, broadcast it again
func (b *BaseOrderBroadcaster) Start(ctx context.Context) {
	log.Debug("BaseOrderBroadcaster start")

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.Stop()
			return
		case <-ticker.C:
			b.broadcastOrders()
			b.broadcastPendingCheck()
		}
	}
}

func (b *BaseOrderBroadcaster) Stop() {
}

// broadcastOrders is a function that broadcasts withdrawal and consolidation orders to the network
func (b *BaseOrderBroadcaster) broadcastOrders() {
	l2Info := b.state.GetL2Info()
	if l2Info.Syncing {
		log.Infof("OrderBroadcaster broadcastOrders ignore, layer2 is catching up")
		return
	}

	btcState := b.state.GetBtcHead()
	if btcState.Syncing {
		log.Infof("OrderBroadcaster broadcastOrders ignore, btc is catching up")
		return
	}
	if btcState.NetworkFee > uint64(config.AppConfig.BTCMaxNetworkFee) {
		log.Infof("OrderBroadcaster broadcastOrders ignore, btc network fee too high: %d", btcState.NetworkFee)
		return
	}

	b.txBroadcastMu.Lock()
	defer b.txBroadcastMu.Unlock()

	epochVoter := b.state.GetEpochVoter()
	if epochVoter.Proposer != config.AppConfig.RelayerAddress {
		log.Debugf("OrderBroadcaster broadcastOrders ignore, self is not proposer, epoch: %d, proposer: %s", epochVoter.Epoch, epochVoter.Proposer)
		return
	}

	// 2. check if there is a sig in progress
	// if b.txBroadcastStatus {
	// 	log.Debug("WalletServer broadcastOrders ignore, there is a broadcast in progress")
	// 	return
	// }
	// if l2Info.LatestBtcHeight <= b.txBroadcastFinishBtcHeight+1 {
	// 	log.Debugf("WalletServer broadcastOrders ignore, last finish broadcast in this block: %d", b.txBroadcastFinishBtcHeight)
	// 	return
	// }

	// TODO: limit the number of orders to broadcast
	sendOrders, err := b.state.GetSendOrderInitlized()
	if err != nil {
		log.Errorf("OrderBroadcaster broadcastOrders error: %v", err)
		return
	}
	if len(sendOrders) == 0 {
		log.Debug("OrderBroadcaster broadcastOrders ignore, no withdraw for broadcast")
		return
	}

	log.Infof("OrderBroadcaster broadcastOrders found %d orders to broadcast", len(sendOrders))

	for i, sendOrder := range sendOrders {
		log.Debugf("OrderBroadcaster broadcastOrders order broadcasting %d/%d, txid: %s", i, len(sendOrders), sendOrder.Txid)
		tx, err := types.DeserializeTransaction(sendOrder.NoWitnessTx)
		if err != nil {
			log.Errorf("OrderBroadcaster broadcastOrders deserialize tx error: %v, txid: %s", err, sendOrder.Txid)
			continue
		}

		utxos, err := b.state.GetUtxoByOrderId(sendOrder.OrderId)
		if err != nil {
			log.Errorf("OrderBroadcaster broadcastOrders get utxos error: %v, txid: %s", err, sendOrder.Txid)
			continue
		}

		// broadcast the transaction and update sendOrder status
		txHash, exist, err := b.remoteClient.SendRawTransaction(tx, utxos, sendOrder.OrderType)
		if err != nil {
			log.Errorf("OrderBroadcaster broadcastOrders send raw transaction error: %v, txid: %s", err, sendOrder.Txid)
			if exist {
				log.Warnf("OrderBroadcaster broadcastOrders tx already in chain, txid: %s, err: %v", sendOrder.Txid, err)
			}
			continue
		}

		// update sendOrder status to pending
		err = b.state.UpdateSendOrderPending(sendOrder.Txid, txHash)
		if err != nil {
			log.Errorf("OrderBroadcaster broadcastOrders update sendOrder status error: %v, txid: %s", err, sendOrder.Txid)
			continue
		}

		log.Infof("WalletServer broadcastOrders tx broadcast success, txid: %s", txHash)
	}
}

// broadcastPendingCheck is a function that checks the pending status of the orders
// if it is failed, broadcast it again
func (b *BaseOrderBroadcaster) broadcastPendingCheck() {
	// TODO: start id
	// Assume limit 50 pending orders at a time
	pendingOrders, err := b.state.GetSendOrderPending(50)
	if err != nil {
		log.Errorf("OrderBroadcaster broadcastPendingCheck error getting pending orders: %v", err)
		return
	}
	if len(pendingOrders) == 0 {
		log.Debug("OrderBroadcaster broadcastPendingCheck no pending orders found")
		return
	}

	for _, pendingOrder := range pendingOrders {
		revert, confirmations, blockHeight, err := b.remoteClient.CheckPending(pendingOrder.Txid, pendingOrder.ExternalTxId, pendingOrder.UpdatedAt)
		if err != nil {
			log.Errorf("OrderBroadcaster broadcastPendingCheck check pending error: %v, txid: %s", err, pendingOrder.Txid)
			continue
		}

		if revert {
			log.Warnf("OrderBroadcaster broadcastPendingCheck tx failed, reverting order: %s", pendingOrder.Txid)
			err := b.state.UpdateSendOrderInitlized(pendingOrder.Txid, pendingOrder.ExternalTxId)
			if err != nil {
				log.Errorf("OrderBroadcaster broadcastPendingCheck revert order to re-initialized error: %v, txid: %s", err, pendingOrder.Txid)
			}
			continue
		}

		if confirmations >= uint64(config.AppConfig.BTCConfirmations) {
			log.Infof("OrderBroadcaster broadcastPendingCheck tx confirmed, txid: %s", pendingOrder.Txid)
			err := b.state.UpdateSendOrderConfirmed(pendingOrder.Txid, uint64(blockHeight))
			if err != nil {
				log.Errorf("OrderBroadcaster broadcastPendingCheck update confirmed order error: %v, txid: %s", err, pendingOrder.Txid)
			}
			continue
		}

		log.Debugf("OrderBroadcaster broadcastPendingCheck tx still pending, txid: %s, confirmations: %d", pendingOrder.Txid, confirmations)
	}
}
