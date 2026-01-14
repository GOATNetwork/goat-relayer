package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
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
	CheckPending(txid string, externalTxId string, updatedAt time.Time) (revert bool, confirmations uint64, blockHeight uint64, err error)
}

type BtcClient struct {
	client *rpcclient.Client
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

// sendRawTransaction sends a raw transaction using RawRequest.
// This method is compatible with all Bitcoin RPC implementations (btcd, Bitcoin Core, GetBlock, etc.)
// as it bypasses the rpcclient's BackendVersion detection which calls getinfo (often blocked by RPC providers).
func sendRawTransaction(client *rpcclient.Client, tx *wire.MsgTx) error {
	// Serialize tx to hex
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return fmt.Errorf("failed to serialize tx: %v", err)
	}
	txHex := hex.EncodeToString(buf.Bytes())

	// Use RawRequest with only hex parameter (most compatible format)
	rawResp, err := client.RawRequest("sendrawtransaction", []json.RawMessage{
		json.RawMessage(fmt.Sprintf("%q", txHex)),
	})
	if err != nil {
		// RawRequest returns *btcjson.RPCError for JSON-RPC errors, return as-is for proper error handling
		if _, ok := err.(*btcjson.RPCError); ok {
			return err
		}
		// Fallback: string matching for non-standard error responses
		errStr := err.Error()
		// ErrRPCTxAlreadyInChain (-27): Transaction already in block chain
		// Bitcoin Core < 28.0: "Transaction already in block chain"
		// Bitcoin Core >= 28.0: "Transaction outputs already in utxo set"
		// btcd: "transaction already exists in blockchain"
		if strings.Contains(errStr, "already in block chain") ||
			strings.Contains(errStr, "already exists in blockchain") ||
			strings.Contains(errStr, "already in utxo set") {
			return &btcjson.RPCError{Code: btcjson.ErrRPCTxAlreadyInChain, Message: errStr}
		}
		// ErrRPCVerifyRejected (-26): Transaction verification failed
		if strings.Contains(errStr, "mandatory-script-verify-flag-failed") ||
			strings.Contains(errStr, "non-mandatory-script-verify-flag") ||
			strings.Contains(errStr, "bad-txns") ||
			strings.Contains(errStr, "txn-mempool-conflict") ||
			strings.Contains(errStr, "insufficient fee") ||
			strings.Contains(errStr, "min relay fee not met") {
			return &btcjson.RPCError{Code: btcjson.ErrRPCVerifyRejected, Message: errStr}
		}
		return err
	}

	// Handle empty response
	if len(rawResp) == 0 || string(rawResp) == "null" || string(rawResp) == "" {
		return fmt.Errorf("sendrawtransaction returned empty response")
	}

	var txid string
	if err := json.Unmarshal(rawResp, &txid); err != nil {
		return fmt.Errorf("unmarshal txid: %w, raw: %s", err, string(rawResp))
	}
	log.Infof("SendRawTransaction success, txid: %s", txid)
	return nil
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

	log.Infof("Fireblocks transaction query response, extTxId: %s, status: %s, subStatus: %s", externalTxId, txDetails.Status, txDetails.SubStatus)

	failedStatus := []string{"CANCELLING", "CANCELLED", "BLOCKED", "REJECTED", "FAILED"}
	// Check if txDetails.Status is in failedStatus
	for _, status := range failedStatus {
		if txDetails.Status == status {
			return true, 0, 0, nil
		}
	}

	// if tx is completed, broadcast to BTC chain
	if txDetails.Status == "COMPLETED" {
		if len(txDetails.SignedMessages) == 0 {
			log.Errorf("No signed messages found for completed tx, txid: %s, fbId: %s", txid, txDetails.ID)
			return true, 0, 0, nil
		}
		// find the send order
		sendOrder, err := c.state.GetSendOrderByTxIdOrExternalId(txid)
		if err != nil {
			return false, 0, 0, fmt.Errorf("get send order error: %v, txid: %s", err, txid)
		}
		// deserialize the tx
		tx, err := types.DeserializeTransaction(sendOrder.NoWitnessTx)
		if err != nil {
			return false, 0, 0, fmt.Errorf("deserialize tx error: %v, txid: %s", err, sendOrder.Txid)
		}
		utxos, err := c.state.GetUtxoByOrderId(sendOrder.OrderId)
		if err != nil {
			return false, 0, 0, fmt.Errorf("get utxos error: %v, txid: %s", err, sendOrder.Txid)
		}
		err = ApplyFireblocksSignaturesToTx(tx, utxos, txDetails.SignedMessages, types.GetBTCNetwork(config.AppConfig.BTCNetworkType))
		if err != nil {
			return false, 0, 0, fmt.Errorf("apply fireblocks signatures to tx error: %v, txid: %s", err, txid)
		}
		err = sendRawTransaction(c.btcRpc, tx)
		if err != nil {
			if rpcErr, ok := err.(*btcjson.RPCError); ok {
				switch rpcErr.Code {
				case btcjson.ErrRPCTxAlreadyInChain:
					txHash, err := chainhash.NewHashFromStr(txid)
					if err != nil {
						return false, 0, 0, fmt.Errorf("new hash from str error: %v, raw txid: %s", err, txid)
					}

					txRawResult, err := c.btcRpc.GetRawTransactionVerbose(txHash)
					if err != nil {
						return false, 0, 0, fmt.Errorf("get raw transaction verbose error: %v, raw txid: %s", err, txid)
					}

					blockHash, err := chainhash.NewHashFromStr(txRawResult.BlockHash)
					if err != nil {
						return false, 0, 0, fmt.Errorf("get block hash error: %v, raw block hash: %s", err, txRawResult.BlockHash)
					}

					// query block
					block, err := c.btcRpc.GetBlockVerbose(blockHash)
					if err != nil {
						return false, 0, 0, fmt.Errorf("get block verbose error: %v, block hash: %s", err, blockHash.String())
					}
					return false, uint64(block.Confirmations), uint64(block.Height), nil
				case btcjson.ErrRPCVerifyRejected:
					if strings.Contains(rpcErr.Message, "mandatory-script-verify-flag-failed") {
						log.Warnf("Transaction signature verification failed, reverting for re-signing: %v, txid: %s", rpcErr, txid)
						return true, 0, 0, nil
					} else {
						log.Warnf("Transaction signature verification failed, error reason: %v, txid: %s", rpcErr, txid)
						return false, 0, 0, fmt.Errorf("send raw transaction error: %v, txid: %s", err, txid)
					}
				}
			}
			return false, 0, 0, fmt.Errorf("send raw transaction error: %v, txid: %s", err, txid)
		}
		return false, 0, 0, nil
	}

	txHash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return false, 0, 0, fmt.Errorf("new hash from str error: %v, raw txid: %s", err, txid)
	}

	txRawResult, err := c.btcRpc.GetRawTransactionVerbose(txHash)
	if err != nil {
		return false, 0, 0, fmt.Errorf("get raw transaction verbose error: %v, raw txid: %s", err, txid)
	}

	blockHash, err := chainhash.NewHashFromStr(txRawResult.BlockHash)
	if err != nil {
		return false, 0, 0, fmt.Errorf("get block hash error: %v, raw block hash: %s", err, txRawResult.BlockHash)
	}

	// query block
	block, err := c.btcRpc.GetBlockVerbose(blockHash)
	if err != nil {
		return false, 0, 0, fmt.Errorf("get block verbose error: %v, block hash: %s", err, blockHash.String())
	}

	return false, uint64(block.Confirmations), uint64(block.Height), nil
}

func NewOrderBroadcaster(btcClient *rpcclient.Client, state *state.State) OrderBroadcaster {
	orderBroadcaster := &BaseOrderBroadcaster{
		state:         state,
		txBroadcastCh: make(chan interface{}, 100),
	}
	if config.AppConfig.BTCNetworkType == "regtest" {
		orderBroadcaster.remoteClient = &BtcClient{
			client: btcClient,
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

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.Stop()
			return
		case msg := <-b.txBroadcastCh:
			msgOrder, ok := msg.(types.MsgSendOrderBroadcasted)
			if !ok {
				log.Errorf("Invalid send order data type")
				continue
			}
			// update send order status to pending
			var order db.SendOrder
			if err := json.Unmarshal(msgOrder.SendOrder, &order); err != nil {
				log.Errorf("SigReceive SendOrder txid %s external id %s unmarshal send order err: %v", msgOrder.TxId, msgOrder.ExternalTxId, err)
				continue
			}
			var utxos []*db.Utxo
			if err := json.Unmarshal(msgOrder.Utxos, &utxos); err != nil {
				log.Errorf("SigReceive SendOrder txid %s external id %s unmarshal utxos err: %v", msgOrder.TxId, msgOrder.ExternalTxId, err)
				continue
			}
			tx, err := types.DeserializeTransaction(order.NoWitnessTx)
			if err != nil {
				log.Errorf("SigReceive SendOrder txid %s external id %s deserialize tx err: %v", msgOrder.TxId, msgOrder.ExternalTxId, err)
				continue
			}
			utxoAmount := int64(order.TxFee)
			network := types.GetBTCNetwork(config.AppConfig.BTCNetworkType)
			var vins []*db.Vin
			for _, txIn := range tx.TxIn {
				vin := &db.Vin{
					OrderId:      order.OrderId,
					BtcHeight:    uint64(txIn.PreviousOutPoint.Index),
					Txid:         txIn.PreviousOutPoint.Hash.String(),
					OutIndex:     int(txIn.PreviousOutPoint.Index),
					SigScript:    nil,
					SubScript:    nil,
					Sender:       "",
					ReceiverType: db.WALLET_TYPE_UNKNOWN, // recover mode uses unknown
					Source:       db.ORDER_TYPE_WITHDRAWAL,
					Status:       db.ORDER_STATUS_INIT,
					UpdatedAt:    time.Now(),
				}
				vins = append(vins, vin)
			}
			var vouts []*db.Vout
			for i, txOut := range tx.TxOut {
				_, addresses, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, network)
				if err != nil {
					continue
				}
				withdrawId := ""
				if len(msgOrder.WithdrawIds) > i {
					withdrawId = fmt.Sprintf("%d", msgOrder.WithdrawIds[i])
				}
				vout := &db.Vout{
					OrderId:    order.OrderId,
					BtcHeight:  0,
					Txid:       tx.TxID(),
					OutIndex:   i,
					WithdrawId: withdrawId,
					Amount:     int64(txOut.Value),
					Receiver:   addresses[0].EncodeAddress(),
					Sender:     "",
					Source:     db.ORDER_TYPE_WITHDRAWAL,
					Status:     db.ORDER_STATUS_INIT,
					UpdatedAt:  time.Now(),
				}
				utxoAmount += txOut.Value
				vouts = append(vouts, vout)
			}
			err = b.state.UpdateSendOrderPending(msgOrder.TxId, msgOrder.ExternalTxId, msgOrder.WithdrawIds, &order, utxos, vins, vouts)
			if err != nil {
				log.Errorf("SigReceive SendOrder txid %s external id %s update send order status err: %v", msgOrder.TxId, msgOrder.ExternalTxId, err)
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
		err = b.state.UpdateSendOrderPending(sendOrder.Txid, externalTxId, nil, nil, nil, nil, nil)
		if err != nil {
			log.Errorf("OrderBroadcaster broadcastOrders update sendOrder status error: %v, txid: %s", err, sendOrder.Txid)
			continue
		}

		orderBytes, err := json.Marshal(sendOrder)
		if err != nil {
			log.Errorf("OrderBroadcaster broadcastOrders marshal sendOrder error: %v, txid: %s", err, sendOrder.Txid)
			continue
		}
		utxoBytes, err := json.Marshal(utxos)
		if err != nil {
			log.Errorf("OrderBroadcaster broadcastOrders marshal utxos error: %v, txid: %s", err, sendOrder.Txid)
			continue
		}
		var withdrawIds []uint64
		if sendOrder.OrderType == db.ORDER_TYPE_WITHDRAWAL {
			withdraws, err := b.state.GetWithdrawsByOrderId(sendOrder.OrderId)
			if err != nil {
				log.Errorf("OrderBroadcaster broadcastOrders get withdraws error: %v, txid: %s", err, sendOrder.Txid)
				continue
			}
			for _, withdraw := range withdraws {
				withdrawIds = append(withdrawIds, withdraw.RequestId)
			}
		}
		p2p.PublishMessage(context.Background(), p2p.Message[any]{
			MessageType: p2p.MessageTypeSendOrderBroadcasted,
			RequestId:   fmt.Sprintf("TXBROADCAST:%s:%s", config.AppConfig.RelayerAddress, sendOrder.Txid),
			DataType:    "MsgSendOrderBroadcasted",
			Data: types.MsgSendOrderBroadcasted{
				TxId:         sendOrder.Txid,
				ExternalTxId: externalTxId,
				SendOrder:    orderBytes,
				Utxos:        utxoBytes,
				WithdrawIds:  withdrawIds,
			},
		})

		log.Infof("OrderBroadcaster broadcastOrders tx broadcast success, txid: %s", sendOrder.Txid)
		time.Sleep(time.Second)
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
		time.Sleep(time.Second)
	}
}
