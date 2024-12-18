package wallet

import (
	"context"
	"encoding/base64"
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
	"github.com/goatnetwork/goat-relayer/internal/p2p"
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
	CheckPending(txid string, externalTxId string, updatedAt time.Time) (status TxStatus, confirmations uint64, blockHeight uint64, err error)
}

type BtcClient struct {
	client *rpcclient.Client
	state  *state.State
}

type FireblocksClient struct {
	client *http.FireblocksProposal
	btcRpc *rpcclient.Client
	state  *state.State
}

type BaseOrderBroadcaster struct {
	remoteClient RemoteClient
	state        *state.State

	txBroadcastMu sync.Mutex
	txBroadcastCh chan interface{}
	// txBroadcastStatus          bool
	// txBroadcastFinishBtcHeight uint64
}

var (
	_ RemoteClient = (*BtcClient)(nil)
	_ RemoteClient = (*FireblocksClient)(nil)

	_ OrderBroadcaster = (*BaseOrderBroadcaster)(nil)
)

// TxStatus represents the status of a transaction
type TxStatus int

const (
	// TxStatusNormal indicates the transaction is normal (confirmed or still pending)
	TxStatusNormal TxStatus = iota
	// TxStatusRevert indicates the transaction should be reverted
	TxStatusRevert
	// TxStatusNeedRBF indicates the transaction needs RBF
	TxStatusNeedRBF
)

func (c *BtcClient) SendRawTransaction(tx *wire.MsgTx, utxos []*db.Utxo, orderType string) (txHash string, exist bool, err error) {
	txid := tx.TxHash().String()
	if len(config.AppConfig.FireblocksSecret) == 0 {
		return txid, false, fmt.Errorf("privKey is not set")
	}
	privKeyBytes, err := hex.DecodeString(config.AppConfig.FireblocksSecret)
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

func (c *BtcClient) CheckPending(txid string, externalTxId string, updatedAt time.Time) (status TxStatus, confirmations uint64, blockHeight uint64, err error) {
	txHash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return TxStatusNormal, 0, 0, fmt.Errorf("new hash from str error: %v, raw txid: %s", err, txid)
	}

	txRawResult, err := c.client.GetRawTransactionVerbose(txHash)
	if err != nil {
		return c.handleTxNotFoundError(err, txid, updatedAt)
	}

	blockHash, err := chainhash.NewHashFromStr(txRawResult.BlockHash)
	if err != nil {
		return TxStatusNormal, 0, 0, fmt.Errorf("new hash from str error: %v, raw block hash: %s", err, txRawResult.BlockHash)
	}

	// query block
	block, err := c.client.GetBlockVerbose(blockHash)
	if err != nil {
		return TxStatusNormal, 0, 0, fmt.Errorf("get block verbose error: %v, block hash: %s", err, blockHash.String())
	}

	// if found, return confirmations and block height
	return TxStatusNormal, txRawResult.Confirmations, uint64(block.Height), nil
}

// handleTxNotFoundError handle tx not found error
func (c *BtcClient) handleTxNotFoundError(err error, txid string, updatedAt time.Time) (status TxStatus, confirmations uint64, blockHeight uint64, errR error) {
	if rpcErr, ok := err.(*btcjson.RPCError); ok && rpcErr.Code == btcjson.ErrRPCNoTxInfo {
		timeDuration := time.Since(updatedAt)

		// if tx not found in 10 minutes to 20 minutes or over 72 hours, revert
		if c.shouldRevert(timeDuration) {
			return c.checkMempoolAndRevert(txid, timeDuration)
		}

		// if tx not found in 10 minutes to 20 minutes or over 72 hours, waiting
		log.Infof("Transaction not found yet, waiting for more time, txid: %s", txid)
		return TxStatusNormal, 0, 0, nil
	}

	return TxStatusNormal, 0, 0, fmt.Errorf("get raw transaction verbose error: %v, txid: %s", err, txid)
}

// shouldRevert check if revert is needed
func (c *BtcClient) shouldRevert(timeDuration time.Duration) bool {
	return (timeDuration >= 10*time.Minute && timeDuration <= 20*time.Minute) || timeDuration > 72*time.Hour
}

// checkMempoolAndRevert check mempool and revert
func (c *BtcClient) checkMempoolAndRevert(txid string, timeDuration time.Duration) (status TxStatus, confirmations uint64, blockHeight uint64, err error) {
	_, err = c.client.GetMempoolEntry(txid)
	if err == nil {
		// if tx in mempool, it is pending
		log.Infof("Transaction is still in mempool, waiting, txid: %s", txid)
		return TxStatusNormal, 0, 0, nil
	}

	if rpcErr, ok := err.(*btcjson.RPCError); ok && rpcErr.Code == btcjson.ErrRPCClientMempoolDisabled {
		log.Warnf("Mempool is disabled, txid: %s", txid)
		// if mempool is disabled, and time less than 72 hours, record warning
		if timeDuration <= 72*time.Hour {
			return TxStatusNormal, 0, 0, fmt.Errorf("mempool is disabled, txid: %s", txid)
		}
	}

	// if tx not found or mempool is disabled, revert
	log.Warnf("Transaction not found in %d minutes, reverting for re-submission, txid: %s", uint64(timeDuration.Minutes()), txid)
	return TxStatusRevert, 0, 0, nil
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

func (c *FireblocksClient) CheckPending(txid string, externalTxId string, updatedAt time.Time) (status TxStatus, confirmations uint64, blockHeight uint64, err error) {
	txDetails, err := c.client.QueryTransaction(externalTxId)
	if err != nil {
		return TxStatusNormal, 0, 0, fmt.Errorf("get tx details from fireblocks error: %v, txid: %s", err, txid)
	}

	failedStatus := []string{"CANCELLING", "CANCELLED", "BLOCKED", "REJECTED", "FAILED"}
	// Check if txDetails.Status is in failedStatus
	for _, status := range failedStatus {
		if txDetails.Status == status {
			return TxStatusRevert, 0, 0, nil
		}
	}

	// if tx is completed, broadcast to BTC chain
	if txDetails.Status == "COMPLETED" {
		if len(txDetails.SignedMessages) == 0 {
			log.Errorf("No signed messages found for completed tx, txid: %s, fbId: %s", txid, txDetails.ID)
			return TxStatusRevert, 0, 0, nil
		}
		// find the send order
		sendOrder, err := c.state.GetSendOrderByTxIdOrExternalId(txid)
		if err != nil {
			return TxStatusNormal, 0, 0, fmt.Errorf("get send order error: %v, txid: %s", err, txid)
		}
		// deserialize the tx
		tx, err := types.DeserializeTransaction(sendOrder.NoWitnessTx)
		if err != nil {
			return TxStatusNormal, 0, 0, fmt.Errorf("deserialize tx error: %v, txid: %s", err, sendOrder.Txid)
		}
		utxos, err := c.state.GetUtxoByOrderId(sendOrder.OrderId)
		if err != nil {
			return TxStatusNormal, 0, 0, fmt.Errorf("get utxos error: %v, txid: %s", err, sendOrder.Txid)
		}
		err = ApplyFireblocksSignaturesToTx(tx, utxos, txDetails.SignedMessages, types.GetBTCNetwork(config.AppConfig.BTCNetworkType))
		if err != nil {
			return TxStatusNormal, 0, 0, fmt.Errorf("apply fireblocks signatures to tx error: %v, txid: %s", err, txid)
		}
		_, err = c.btcRpc.SendRawTransaction(tx, false)
		if err != nil {
			if rpcErr, ok := err.(*btcjson.RPCError); ok {
				switch rpcErr.Code {
				case btcjson.ErrRPCTxAlreadyInChain:
					return TxStatusNormal, 0, 0, nil
				// ErrRPCVerifyRejected indicates that transaction or block was rejected by network rules
				case btcjson.ErrRPCVerifyRejected:
					log.Warnf("transaction was rejected by network rules, reverting for re-signing: %v, txid: %s", rpcErr, txid)
					return TxStatusRevert, 0, 0, nil
				}
			}
			return TxStatusNormal, 0, 0, fmt.Errorf("send raw transaction error: %v, txid: %s", err, txid)
		}
		return TxStatusNormal, 0, 0, nil
	}

	// Check if RBF is needed when transaction has no confirmations
	if txDetails.NumOfConfirmations == 0 {
		pendingDuration := time.Since(updatedAt)
		needsRBF := false

		// Get current network fee
		btcState := c.state.GetBtcHead()
		networkFee := btcState.NetworkFee.FastestFee

		// Check if transaction is stuck or pending too long
		if pendingDuration > config.AppConfig.BTCStuckTimeout {
			needsRBF = true
			log.Warnf("Transaction stuck for too long: %s, duration: %v", txid, pendingDuration)
		} else if pendingDuration > config.AppConfig.BTCRBFTimeout {
			// Get the original transaction and compare fees
			sendOrder, err := c.state.GetSendOrderByTxIdOrExternalId(txid)
			if err != nil {
				log.Errorf("Failed to get send order for RBF check: %v, txid: %s", err, txid)
			} else {
				originalFeeRate := sendOrder.TxPrice
				if float64(networkFee) > float64(originalFeeRate)*config.AppConfig.BTCRBFMultiplier {
					needsRBF = true
					log.Warnf("Network fee increased significantly: %d -> %d, attempting RBF for tx: %s",
						originalFeeRate, networkFee, txid)
				}
			}
		}

		if needsRBF {
			return TxStatusNeedRBF, 0, 0, nil
		}
	}

	blockHeight, err = strconv.ParseUint(txDetails.BlockInfo.BlockHeight, 10, 64)
	if err != nil {
		return TxStatusNormal, 0, 0, fmt.Errorf("parse block height error: %v, txid: %s", err, txid)
	}

	return TxStatusNormal, uint64(txDetails.NumOfConfirmations), blockHeight, nil
}

func NewOrderBroadcaster(btcClient *rpcclient.Client, state *state.State) OrderBroadcaster {
	orderBroadcaster := &BaseOrderBroadcaster{
		state:         state,
		txBroadcastCh: make(chan interface{}, 100),
	}
	if config.AppConfig.BTCNetworkType == "regtest" {
		orderBroadcaster.remoteClient = &BtcClient{
			client: btcClient,
			state:  state,
		}
	} else {
		orderBroadcaster.remoteClient = &FireblocksClient{
			client: http.NewFireblocksProposal(),
			btcRpc: btcClient,
			state:  state,
		}
	}
	return orderBroadcaster
}

// txBroadcastLoop is a loop that broadcasts withdrawal and consolidation orders to the network
// check orders pending status, if it is failed, broadcast it again
func (b *BaseOrderBroadcaster) Start(ctx context.Context) {
	log.Debug("BaseOrderBroadcaster start")
	b.state.EventBus.Subscribe(state.SendOrderBroadcasted, b.txBroadcastCh)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.Stop()
			return
		case msg := <-b.txBroadcastCh:
			sendOrder, ok := msg.(types.MsgSendOrderBroadcasted)
			if !ok {
				log.Errorf("Invalid send order data type")
				continue
			}
			err := b.state.UpdateSendOrderPending(sendOrder.TxId, sendOrder.ExternalTxId)
			if err != nil {
				log.Errorf("Failed to update send order status: %v", err)
				continue
			}
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
	if btcState.NetworkFee.FastestFee > uint64(config.AppConfig.BTCMaxNetworkFee) {
		log.Infof("OrderBroadcaster broadcastOrders ignore, btc network fee too high: %v", btcState.NetworkFee)
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
		externalTxId, exist, err := b.remoteClient.SendRawTransaction(tx, utxos, sendOrder.OrderType)
		if err != nil {
			log.Errorf("OrderBroadcaster broadcastOrders send raw transaction error: %v, txid: %s", err, sendOrder.Txid)
			if exist {
				log.Warnf("OrderBroadcaster broadcastOrders tx already in chain, txid: %s, err: %v", sendOrder.Txid, err)
			}
			continue
		}

		// update sendOrder status to pending
		err = b.state.UpdateSendOrderPending(sendOrder.Txid, externalTxId)
		if err != nil {
			log.Errorf("OrderBroadcaster broadcastOrders update sendOrder status error: %v, txid: %s", err, sendOrder.Txid)
			continue
		}

		p2p.PublishMessage(context.Background(), p2p.Message[any]{
			MessageType: p2p.MessageTypeSendOrderBroadcasted,
			RequestId:   fmt.Sprintf("TXBROADCAST:%s:%s", config.AppConfig.RelayerAddress, sendOrder.Txid),
			DataType:    "MsgSendOrderBroadcasted",
			Data: types.MsgSendOrderBroadcasted{
				TxId:         sendOrder.Txid,
				ExternalTxId: externalTxId,
			},
		})

		log.Infof("OrderBroadcaster broadcastOrders tx broadcast success, txid: %s", sendOrder.Txid)
	}
}

// broadcastPendingCheck is a function that checks the pending status of the orders
// if it is failed, broadcast it again
func (b *BaseOrderBroadcaster) broadcastPendingCheck() {
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
		status, confirmations, blockHeight, err := b.remoteClient.CheckPending(pendingOrder.Txid, pendingOrder.ExternalTxId, pendingOrder.UpdatedAt)
		if err != nil {
			log.Errorf("OrderBroadcaster broadcastPendingCheck check pending error: %v, txid: %s", err, pendingOrder.Txid)
			continue
		}

		switch status {
		case TxStatusRevert:
			log.Warnf("OrderBroadcaster broadcastPendingCheck tx failed, reverting order: %s", pendingOrder.Txid)
			err := b.state.UpdateSendOrderInitlized(pendingOrder.Txid, pendingOrder.ExternalTxId)
			if err != nil {
				log.Errorf("OrderBroadcaster broadcastPendingCheck revert order to re-initialized error: %v, txid: %s", err, pendingOrder.Txid)
			}

		case TxStatusNeedRBF:
			log.Infof("OrderBroadcaster broadcastPendingCheck tx needs RBF: %s", pendingOrder.Txid)
			// Get the original transaction details
			sendOrder, err := b.state.GetSendOrderByTxIdOrExternalId(pendingOrder.OrderId)
			if err != nil {
				log.Errorf("Failed to get send order for RBF: %v, txid: %s", err, pendingOrder.Txid)
				continue
			}

			utxos, err := b.state.GetUtxoByOrderId(sendOrder.OrderId)
			if err != nil {
				log.Errorf("Failed to get UTXOs for RBF: %v, orderId: %s", err, sendOrder.OrderId)
				continue
			}

			withdraws, err := b.state.GetWithdrawsByOrderId(sendOrder.OrderId)
			if err != nil {
				log.Errorf("Failed to get withdraws for RBF: %v, orderId: %s", err, sendOrder.OrderId)
				continue
			}

			// Create replacement transaction with higher fee
			btcState := b.state.GetBtcHead()
			networkFee := btcState.NetworkFee.FastestFee
			newFeeRate := int64(float64(networkFee) * config.AppConfig.BTCRBFMultiplier)

			tx, err := types.DeserializeTransaction(sendOrder.NoWitnessTx)
			if err != nil {
				log.Errorf("Failed to deserialize transaction for RBF: %v, txid: %s", err, pendingOrder.Txid)
				continue
			}

			pubkey, err := b.state.GetDepositKeyByBtcBlock(0)
			if err != nil {
				log.Fatalf("WalletServer get current change or consolidation key by btc height current err %v", err)
			}

			network := types.GetBTCNetwork(config.AppConfig.BTCNetworkType)
			pubkeyBytes, err := base64.StdEncoding.DecodeString(pubkey.PubKey)
			if err != nil {
				log.Fatalf("Base64 decode pubkey %s err %v", pubkey.PubKey, err)
			}
			changeAddress, err := types.GenerateP2WPKHAddress(pubkeyBytes, network)
			if err != nil {
				log.Fatalf("Gen P2WPKH address from pubkey %s err %v", pubkey.PubKey, err)
			}

			// Calculate total input amount
			var totalInput uint64
			for _, utxo := range utxos {
				totalInput += uint64(utxo.Amount)
			}

			// Calculate total withdraw amount
			var totalWithdraw uint64
			for _, withdraw := range withdraws {
				totalWithdraw += withdraw.Amount
			}

			// Calculate new fee
			txSize := tx.SerializeSize()
			newFee := newFeeRate * int64(txSize)

			// Calculate new change amount
			changeAmount := int64(totalInput) - int64(totalWithdraw) - newFee
			if changeAmount < 0 {
				log.Errorf("Insufficient funds for RBF: total_input=%d, total_withdraw=%d, new_fee=%d", totalInput, totalWithdraw, newFee)
				continue
			}

			newTx, dustWithdrawId, err := ReplaceRawTransaction(
				tx,
				utxos,
				withdraws,
				changeAddress.EncodeAddress(),
				changeAmount,
				newFeeRate,
				int64(networkFee),
				types.GetBTCNetwork(config.AppConfig.BTCNetworkType),
			)
			if err != nil {
				log.Errorf("Failed to create RBF transaction: %v, txid: %s", err, pendingOrder.Txid)
				continue
			}
			if dustWithdrawId > 0 {
				log.Errorf("RBF resulted in dust output: withdraw_id=%d, txid: %s", dustWithdrawId, pendingOrder.Txid)
				continue
			}

			// Save and broadcast the new transaction
			noWitnessTx, err := types.SerializeTransactionNoWitness(newTx)
			if err != nil {
				log.Errorf("Failed to serialize RBF transaction: %v", err)
				continue
			}

			// Update the order with new transaction details
			err = b.state.UpdateSendOrderRBF(pendingOrder.Txid, noWitnessTx, uint64(newFeeRate))
			if err != nil {
				log.Errorf("Failed to update order for RBF: %v, txid: %s", err, pendingOrder.Txid)
				continue
			}

			// Broadcast the new transaction
			_, exist, err := b.remoteClient.SendRawTransaction(newTx, utxos, sendOrder.OrderType)
			if err != nil {
				log.Errorf("Failed to broadcast RBF transaction: %v, txid: %s", err, pendingOrder.Txid)
				continue
			}
			if exist {
				log.Infof("RBF transaction already exists in chain or mempool: %s", pendingOrder.Txid)
				continue
			}

			log.Infof("Successfully created and broadcast RBF transaction for txid: %s with new fee rate: %d", pendingOrder.Txid, newFeeRate)

		case TxStatusNormal:
			if confirmations >= uint64(config.AppConfig.BTCConfirmations) {
				log.Infof("OrderBroadcaster broadcastPendingCheck tx confirmed, txid: %s", pendingOrder.Txid)
				err := b.state.UpdateSendOrderConfirmed(pendingOrder.Txid, uint64(blockHeight))
				if err != nil {
					log.Errorf("OrderBroadcaster broadcastPendingCheck update confirmed order error: %v, txid: %s", err, pendingOrder.Txid)
				}
			} else {
				log.Debugf("OrderBroadcaster broadcastPendingCheck tx still pending, txid: %s, confirmations: %d", pendingOrder.Txid, confirmations)
			}
		}
	}
}
