package wallet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/goatnetwork/goat-relayer/internal/types"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

func (w *WalletServer) withdrawLoop(ctx context.Context) {
	w.state.EventBus.Subscribe(state.SigFailed, w.withdrawSigFailChan)
	w.state.EventBus.Subscribe(state.SigFinish, w.withdrawSigFinishChan)
	w.state.EventBus.Subscribe(state.SigTimeout, w.withdrawSigTimeoutChan)

	// init status process, if restart && layer2 status is up to date, remove all status "create", "aggregating"
	if !w.state.GetBtcHead().Syncing {
		w.cleanWithdrawProcess()
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case sigFail := <-w.withdrawSigFailChan:
			w.handleWithdrawSigFailed(sigFail, "failed")
		case sigTimeout := <-w.withdrawSigTimeoutChan:
			w.handleWithdrawSigFailed(sigTimeout, "timeout")
		case sigFinish := <-w.withdrawSigFinishChan:
			w.handleWithdrawSigFinish(sigFinish)
		case <-ticker.C:
			w.initWithdrawSig()
			w.finalizeWithdrawSig()
		}
	}
}

func (w *WalletServer) handleWithdrawSigFailed(event interface{}, reason string) {
	w.sigMu.Lock()
	defer w.sigMu.Unlock()

	switch e := event.(type) {
	case types.MsgSignSendOrder:
		if !w.sigStatus {
			log.Debug("Event handleWithdrawSigFailed ignore, sigStatus is false")
			return
		}
		log.Infof("Event handleWithdrawSigFailed is of type MsgSignSendOrder, request id %s, reason: %s", e.RequestId, reason)
		w.sigStatus = false
	case types.MsgSignFinalizeWithdraw:
		if !w.finalizeWithdrawStatus {
			log.Debug("Event handleWithdrawSigFailed ignore, finalizeWithdrawStatus is false")
			return
		}
		log.Infof("Event handleWithdrawSigFailed is of type MsgSignFinalizeWithdraw, request id %s, reason: %s", e.RequestId, reason)
		w.finalizeWithdrawStatus = false
	default:
		log.Debug("WalletServer withdrawLoop ignore unsupport type")
	}
}

func (w *WalletServer) handleWithdrawSigFinish(event interface{}) {
	w.sigMu.Lock()
	defer w.sigMu.Unlock()

	switch e := event.(type) {
	case types.MsgSignSendOrder:
		if !w.sigStatus {
			log.Debug("Event handleWithdrawSigFinish ignore, sigStatus is false")
			return
		}
		log.Infof("Event handleWithdrawSigFinish is of type MsgSignSendOrder, request id %s", e.RequestId)
		w.sigStatus = false
		w.sigFinishHeight = w.state.GetL2Info().Height
	case types.MsgSignFinalizeWithdraw:
		if !w.finalizeWithdrawStatus {
			log.Debug("Event handleWithdrawSigFinish ignore, finalizeWithdrawStatus is false")
			return
		}
		log.Infof("Event handleWithdrawSigFinish is of type MsgSignFinalizeWithdraw, request id %s", e.RequestId)
		w.finalizeWithdrawStatus = false
	default:
		log.Debug("WalletServer withdrawLoop ignore unsupport type")
	}
}

func (w *WalletServer) initWithdrawSig() {
	log.Debug("WalletServer initWithdrawSig")

	// 1. check catching up, self is proposer
	l2Info := w.state.GetL2Info()
	if l2Info.Syncing {
		log.Infof("WalletServer initWithdrawSig ignore, layer2 is catching up")
		return
	}

	btcState := w.state.GetBtcHead()
	if btcState.Syncing {
		log.Infof("WalletServer initWithdrawSig ignore, btc is catching up")
		return
	}
	if btcState.NetworkFee > 500 {
		log.Infof("WalletServer initWithdrawSig ignore, btc network fee too high: %d", btcState.NetworkFee)
		return
	}

	w.sigMu.Lock()
	defer w.sigMu.Unlock()

	epochVoter := w.state.GetEpochVoter()
	if epochVoter.Proposer != config.AppConfig.RelayerAddress {
		// do not clean immediately
		if w.sigStatus && l2Info.Height > epochVoter.Height+1 {
			w.sigStatus = false
			// clean process, role changed, remove all status "create", "aggregating"
			w.cleanWithdrawProcess()
		}
		log.Debugf("WalletServer initWithdrawSig ignore, self is not proposer, epoch: %d, proposer: %s", epochVoter.Epoch, epochVoter.Proposer)
		return
	}

	// 2. check if there is a sig in progress
	if w.sigStatus {
		log.Debug("WalletServer initWithdrawSig ignore, there is a sig")
		return
	}
	if l2Info.Height <= w.sigFinishHeight+2 {
		log.Debug("WalletServer initWithdrawSig ignore, last finish sig in 2 blocks")
		return
	}
	// clean process, become proposer again, remove all status "create", "aggregating"
	w.cleanWithdrawProcess()

	// 3. query withraw list from db, status 'create'
	// if count > 150, built soon
	// else if count > 50, check oldest one, if than 2 hours (optional), built
	// else if check oldest one, if than 6 hours (optional), built
	// else go to 4
	// 4. do consolidation
	// 5. start bls sig

	// get pubkey
	pubkey, err := w.state.GetDepositKeyByBtcBlock(0)
	if err != nil {
		log.Fatalf("WalletServer get current change or consolidation key by btc height current err %v", err)
	}

	network := types.GetBTCNetwork(config.AppConfig.BTCNetworkType)

	// get vin
	pubkeyBytes, err := base64.StdEncoding.DecodeString(pubkey.PubKey)
	if err != nil {
		log.Fatalf("Base64 decode pubkey %s err %v", pubkey.PubKey, err)
	}
	p2wpkhAddress, err := types.GenerateP2WPKHAddress(pubkeyBytes, network)
	if err != nil {
		log.Fatalf("Gen P2WPKH address from pubkey %s err %v", pubkey.PubKey, err)
	}

	// step 3
	withdraws, err := w.state.GetWithdrawsCanStart()
	if err != nil {
		log.Errorf("WalletServer initWithdrawSig getWithdrawsCanStart error: %v", err)
		return
	}
	if len(withdraws) == 0 {
		log.Infof("WalletServer initWithdrawSig no withdraw from db can start, count: %d", len(withdraws))
		return
	}

	networkFee := int64(btcState.NetworkFee)
	selectedWithdraws, receiverTypes, withdrawAmount, actualPrice, err := SelectWithdrawals(withdraws, networkFee, 150, network)
	if err != nil {
		log.Warnf("WalletServer initWithdrawSig SelectWithdrawals error: %v", err)
		return
	}

	// check if need start bls
	startBls := false
	wCount := len(selectedWithdraws)
	if wCount == 0 {
		log.Infof("WalletServer initWithdrawSig no withdraw after filter can start, count: %d", len(selectedWithdraws))
	} else {
		log.Infof("WalletServer initWithdrawSig SelectWithdrawals, withdrawAmount: %d, actualPrice: %d, selectedWithdraws: %d", withdrawAmount, actualPrice, len(selectedWithdraws))
		if wCount >= 150 {
			startBls = true
			log.Debugf("WalletServer initWithdrawSig set start bls to true, count: %d", wCount)
		} else {
			sort.Slice(selectedWithdraws, func(i, j int) bool {
				return selectedWithdraws[i].CreatedAt.Unix() < selectedWithdraws[j].CreatedAt.Unix()
			})
			waitTime1, waitTime2 := types.WithdrawalWaitTime(config.AppConfig.BTCNetworkType)
			log.Debugf("WalletServer initWithdrawSig waitTime1: %s, waitTime2: %s", waitTime1, waitTime2)
			oldestWithdraw := selectedWithdraws[0]
			if wCount >= 50 && time.Since(oldestWithdraw.CreatedAt) > waitTime1 {
				startBls = true
				log.Debugf("WalletServer initWithdrawSig set start bls to true, count: %d, waitTime1: %s", wCount, waitTime1)
			} else if time.Since(oldestWithdraw.CreatedAt) > waitTime2 {
				startBls = true
				log.Debugf("WalletServer initWithdrawSig set start bls to true, count: %d, waitTime2: %s", wCount, waitTime2)
			}
		}
	}

	utxos, err := w.state.GetUtxoCanSpend()
	if err != nil {
		log.Errorf("WalletServer initWithdrawSig GetUtxoCanSpend error: %v", err)
		return
	}

	var msgSignSendOrder *types.MsgSignSendOrder
	currNetworkFee := btcState.NetworkFee
	if !startBls {
		log.Infof("WalletServer initWithdrawSig withdraw not start bls, count: %d, next to check consolidation", wCount)

		selectedUtxos, totalAmount, finalAmount, err := ConsolidateSmallUTXOs(utxos, int64(currNetworkFee), types.SMALL_UTXO_DEFINE, 50, 0)
		if err != nil {
			log.Errorf("WalletServer initWithdrawSig ConsolidateSmallUTXOs error: %v", err)
			return
		}
		log.Infof("WalletServer initWithdrawSig ConsolidateSmallUTXOs,totalAmount: %d, finalAmount: %d, selectedUtxos: %d", totalAmount, finalAmount, len(selectedUtxos))

		startBls = true

		// create SendOrder for selectedUtxos consolidation
		tx, _, err := CreateRawTransaction(selectedUtxos, nil, p2wpkhAddress.EncodeAddress(), finalAmount, 0, networkFee, network)
		if err != nil {
			log.Errorf("WalletServer initWithdrawSig CreateRawTransaction for consolidation error: %v", err)
			return
		}
		log.Infof("WalletServer initWithdrawSig CreateRawTransaction for consolidation, tx: %s", tx.TxID())

		msgSignSendOrder, err = w.createSendOrder(tx, db.ORDER_TYPE_CONSOLIDATION, selectedUtxos, nil, totalAmount, 0, finalAmount, uint64(totalAmount-finalAmount), currNetworkFee, epochVoter, network)
		if err != nil {
			log.Errorf("WalletServer initWithdrawSig createSendOrder for consolidation error: %v", err)
			return
		}
	} else {
		// create SendOrder for selectedWithdraws
		selectOptimalUTXOs, totalSelectedAmount, _, changeAmount, estimateFee, err := SelectOptimalUTXOs(utxos, receiverTypes, withdrawAmount, actualPrice, len(selectedWithdraws))
		if err != nil {
			log.Errorf("WalletServer initWithdrawSig SelectOptimalUTXOs error: %v", err)
			return
		}
		log.Infof("WalletServer initWithdrawSig SelectOptimalUTXOs, totalSelectedAmount: %d, withdrawAmount: %d, changeAmount: %d, selectedUtxos: %d", totalSelectedAmount, withdrawAmount, changeAmount, len(selectOptimalUTXOs))

		tx, dustWithdrawId, err := CreateRawTransaction(selectOptimalUTXOs, selectedWithdraws, p2wpkhAddress.EncodeAddress(), changeAmount, estimateFee, networkFee, network)
		if err != nil {
			log.Errorf("WalletServer initWithdrawSig CreateRawTransaction for withdraw error: %v", err)
			if dustWithdrawId > 0 {
				// update this withdraw to closed
				err = w.state.CloseWithdraw(dustWithdrawId, "dust limit")
				if err != nil {
					log.Errorf("WalletServer initWithdrawSig CloseWithdraw for dust limit withdraw %d, error: %v", dustWithdrawId, err)
				} else {
					log.Infof("WalletServer initWithdrawSig CloseWithdraw for dust limit withdraw %d ok, ave tx fee %d", dustWithdrawId, estimateFee/int64(len(selectedWithdraws)))
				}
			}
			return
		}
		log.Infof("WalletServer initWithdrawSig CreateRawTransaction for withdraw, tx: %s, network fee rate: %d", tx.TxID(), currNetworkFee)

		msgSignSendOrder, err = w.createSendOrder(tx, db.ORDER_TYPE_WITHDRAWAL, selectOptimalUTXOs, selectedWithdraws, totalSelectedAmount, withdrawAmount, changeAmount, uint64(estimateFee), uint64(actualPrice), epochVoter, network)
		if err != nil {
			log.Errorf("WalletServer initWithdrawSig createSendOrder for withdraw error: %v", err)
			return
		}
	}

	// w.sigStatus should update to false after layer2 InitalWithdraw callback
	if msgSignSendOrder != nil {
		w.sigStatus = true

		// send msg to bus
		w.state.EventBus.Publish(state.SigStart, *msgSignSendOrder)
		log.Infof("WalletServer initWithdrawSig send MsgSignSendOrder to bus, requestId: %s", msgSignSendOrder.MsgSign.RequestId)
	}
}

// createSendOrder, create send order for selected utxos and withdraws (if orderType is consolidation, selectedWithdraws is nil)
func (w *WalletServer) createSendOrder(tx *wire.MsgTx, orderType string, selectedUtxos []*db.Utxo, selectedWithdraws []*db.Withdraw, utxoAmount, withdrawAmount, changeAmount int64, txFee, networkTxPrice uint64, epochVoter db.EpochVoter, network *chaincfg.Params) (*types.MsgSignSendOrder, error) {
	noWitnessTx, err := types.SerializeTransactionNoWitness(tx)
	if err != nil {
		return nil, err
	}
	// save order to db
	order := &db.SendOrder{
		OrderId:     uuid.New().String(),
		Proposer:    config.AppConfig.RelayerAddress,
		Amount:      uint64(utxoAmount),
		TxPrice:     networkTxPrice,
		Status:      db.ORDER_STATUS_AGGREGATING,
		OrderType:   orderType,
		BtcBlock:    0,
		Txid:        tx.TxID(),
		NoWitnessTx: noWitnessTx,
		TxFee:       txFee,
		UpdatedAt:   time.Now(),
	}

	requestId := fmt.Sprintf("SENDORDER:%s:%s", config.AppConfig.RelayerAddress, order.OrderId)

	var withdrawIds []uint64
	var withdrawBytes []byte
	if len(selectedWithdraws) > 0 {
		withdrawBytes, err = json.Marshal(selectedWithdraws)
		if err != nil {
			return nil, err
		}
		for _, withdraw := range selectedWithdraws {
			withdrawIds = append(withdrawIds, withdraw.RequestId)
		}
	}

	var vins []*db.Vin
	for i, txIn := range tx.TxIn {
		vin := &db.Vin{
			OrderId:      order.OrderId,
			BtcHeight:    uint64(txIn.PreviousOutPoint.Index),
			Txid:         txIn.PreviousOutPoint.Hash.String(),
			OutIndex:     int(txIn.PreviousOutPoint.Index),
			SigScript:    nil,
			SubScript:    selectedUtxos[i].SubScript,
			Sender:       "",
			ReceiverType: selectedUtxos[i].ReceiverType,
			Source:       orderType,
			Status:       db.ORDER_STATUS_AGGREGATING,
			UpdatedAt:    time.Now(),
		}
		vins = append(vins, vin)
	}
	var vouts []*db.Vout
	for i, txOut := range tx.TxOut {
		withdrawId := ""
		if orderType == db.ORDER_TYPE_WITHDRAWAL && len(selectedWithdraws) > i {
			withdrawId = fmt.Sprintf("%d", selectedWithdraws[i].RequestId)
		}
		_, addresses, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, network)
		if err != nil {
			return nil, err
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
			Source:     orderType,
			Status:     db.ORDER_STATUS_AGGREGATING,
			UpdatedAt:  time.Now(),
		}
		vouts = append(vouts, vout)
	}

	orderBytes, err := json.Marshal(order)
	if err != nil {
		return nil, err
	}
	utxoBytes, err := json.Marshal(selectedUtxos)
	if err != nil {
		return nil, err
	}

	vinBytes, err := json.Marshal(vins)
	if err != nil {
		return nil, err
	}

	voutBytes, err := json.Marshal(vouts)
	if err != nil {
		return nil, err
	}

	msgSignSendOrder := &types.MsgSignSendOrder{
		MsgSign: types.MsgSign{
			RequestId:    requestId,
			Sequence:     epochVoter.Sequence,
			Epoch:        epochVoter.Epoch,
			IsProposer:   true,
			VoterAddress: epochVoter.Proposer,
			SigData:      nil,
			CreateTime:   time.Now().Unix(),
		},
		SendOrder: orderBytes,
		Utxos:     utxoBytes,
		Vins:      vinBytes,
		Vouts:     voutBytes,
		Withdraws: withdrawBytes,

		WithdrawIds: withdrawIds,
	}

	// save
	err = w.state.CreateSendOrder(order, selectedUtxos, selectedWithdraws, vins, vouts, true)
	if err != nil {
		return nil, err
	}

	return msgSignSendOrder, nil
}

func (w *WalletServer) cleanWithdrawProcess() {
	// unset all status "create", "aggregating"
	err := w.state.CleanProcessingWithdraw()
	if err != nil {
		log.Fatalf("WalletServer cleanWithdrawProcess unexpected error %v", err)
	}
}
