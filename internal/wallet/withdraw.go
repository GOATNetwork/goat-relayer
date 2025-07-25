package wallet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

const (
	CONSOLIDATION_TRIGGER_COUNT  = 150
	CONSOLIDATION_MAX_VIN        = 200
	CONSOLIDATION_THRESHOLD      = 50000000
	WITHDRAW_IMMEDIATE_COUNT     = 32
	WITHDRAW_MAX_VOUT            = 32
	SAFEBOX_TASK_MAX_VOUT        = 1
	SAFEBOX_TASK_IMMEDIATE_COUNT = 1
	SAFEBOX_EXTERNAL_AMOUNT      = 100000
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
			w.cancelWithdrawSig()
		}
	}
}

func (w *WalletServer) handleWithdrawSigFailed(event interface{}, reason string) {
	w.sigMu.Lock()
	defer w.sigMu.Unlock()

	switch e := event.(type) {
	case types.MsgSignSendOrder:
		w.sigFinishHeight = w.state.GetL2Info().Height
		var order db.SendOrder
		err := json.Unmarshal(e.SendOrder, &order)
		if err != nil {
			log.Debug("Cannot unmarshal send order from msg")
			return
		}
		if order.OrderType == db.ORDER_TYPE_SAFEBOX {
			err = w.state.RevertSafeboxTaskToReceivedOKByTimelockTxid(order.Txid)
			if err != nil {
				log.Errorf("Event handleWithdrawSigFailed, clean processing withdraw by order id %s, error: %v", order.OrderId, err)
				return
			}
			log.Infof("Event handleWithdrawSigFailed, clean processing withdraw by order id %s, withdraw ids: %v", order.OrderId, e.WithdrawIds)
		}
		log.Infof("Event handleWithdrawSigFailed, clean processing withdraw by order id %s, withdraw ids: %v", order.OrderId, e.WithdrawIds)
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
	case types.MsgSignCancelWithdraw:
		if !w.cancelWithdrawStatus {
			log.Debug("Event handleWithdrawSigFailed ignore, cancelWithdrawStatus is false")
			return
		}
		log.Infof("Event handleWithdrawSigFailed is of type MsgSignCancelWithdraw, request id %s, reason: %s", e.RequestId, reason)
		w.cancelWithdrawStatus = false
	default:
		log.Debug("WalletServer withdrawLoop ignore unsupport type")
	}
}

func (w *WalletServer) handleWithdrawSigFinish(event interface{}) {
	w.sigMu.Lock()
	defer w.sigMu.Unlock()

	switch e := event.(type) {
	case types.MsgSignSendOrder:
		w.sigFinishHeight = w.state.GetL2Info().Height
		if !w.sigStatus {
			log.Debug("Event handleWithdrawSigFinish ignore, sigStatus is false")
			return
		}
		log.Infof("Event handleWithdrawSigFinish is of type MsgSignSendOrder, request id %s", e.RequestId)
		w.sigStatus = false
	case types.MsgSignFinalizeWithdraw:
		if !w.finalizeWithdrawStatus {
			log.Debug("Event handleWithdrawSigFinish ignore, finalizeWithdrawStatus is false")
			return
		}
		log.Infof("Event handleWithdrawSigFinish is of type MsgSignFinalizeWithdraw, request id %s", e.RequestId)
		w.finalizeWithdrawStatus = false
	case types.MsgSignCancelWithdraw:
		if !w.cancelWithdrawStatus {
			log.Debug("Event handleWithdrawSigFinish ignore, cancelWithdrawStatus is false")
			return
		}
		log.Infof("Event handleWithdrawSigFinish is of type MsgSignCancelWithdraw, request id %s", e.RequestId)
		w.cancelWithdrawStatus = false
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
	if btcState.NetworkFee.FastestFee == 0 {
		log.Warn("WalletServer initWithdrawSig ignore, btc network fee is not available")
		return
	}
	if btcState.NetworkFee.FastestFee > uint64(config.AppConfig.BTCMaxNetworkFee) {
		log.Infof("WalletServer initWithdrawSig ignore, btc network fee too high: %v", btcState.NetworkFee)
		return
	}

	w.sigMu.Lock()
	defer w.sigMu.Unlock()

	epochVoter := w.state.GetEpochVoter()

	// update proposer status
	if l2Info.Height <= epochVoter.Height+5 {
		log.Debugf("WalletServer initWithdrawSig ignore, last proposer change in 5 blocks, proposer: %s", epochVoter.Proposer)
		return
	}
	if epochVoter.Proposer != config.AppConfig.RelayerAddress {
		// do not clean immediately
		if w.sigStatus && l2Info.Height > epochVoter.Height+1 {
			w.sigStatus = false
			// clean process, role changed, remove all status "create", "aggregating"
			w.cleanWithdrawProcess()
			log.Infof("WalletServer detected voter in sig status and conditions met, cleanup executed, self is voter")
		}
		log.Debugf("WalletServer initWithdrawSig ignore, self is not proposer, epoch: %d, proposer: %s", epochVoter.Epoch, epochVoter.Proposer)
		return
	}

	// 2. check if there is a sig in progress
	if w.sigStatus {
		log.Debug("WalletServer initWithdrawSig ignore, there is a sig")
		return
	}
	if l2Info.Height <= w.sigFinishHeight+5 {
		log.Debug("WalletServer initWithdrawSig ignore, last finish sig in 5 blocks")
		return
	}
	// clean process, become proposer again, remove all status "create", "aggregating"
	w.cleanWithdrawProcess()
	log.Infof("WalletServer initWithdrawSig proposer changed, cleanup executed, self is proposer")

	// 3. do consolidation
	// 4. query withraw list from db, status 'create'
	// if count > 150, built soon
	// else if count > 50, check oldest one, if than 10 minutes (optional), built
	// else if check oldest one, if than 20 minutes (optional), built
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

	// get utxos can spend, check consolidation process
	utxos, err := w.state.GetUtxoCanSpend()
	if err != nil {
		log.Errorf("WalletServer initWithdrawSig GetUtxoCanSpend error: %v", err)
		return
	}
	if len(utxos) == 0 {
		log.Warn("WalletServer initWithdrawSig no utxos can spend")
		return
	}

	var msgSignSendOrder *types.MsgSignSendOrder
	networkFee := btcState.NetworkFee

	// check utxo count >= consolidation trigger count and no consolidation in progress
	if len(utxos) >= CONSOLIDATION_TRIGGER_COUNT && !w.state.HasConsolidationInProgress() {
		// 3. start consolidation
		log.Infof("WalletServer initWithdrawSig should start consolidation, utxo count: %d", len(utxos))

		// consolidation fee is always half hour fee
		consolidationFee := networkFee.HalfHourFee

		selectedUtxos, totalAmount, finalAmount, witnessSize, err := ConsolidateUTXOsByCount(utxos, int64(consolidationFee), CONSOLIDATION_THRESHOLD, CONSOLIDATION_MAX_VIN, CONSOLIDATION_TRIGGER_COUNT)
		if err != nil {
			log.Errorf("WalletServer initWithdrawSig ConsolidateUTXOsByCount error: %v", err)
			return
		}
		log.Infof("WalletServer initWithdrawSig ConsolidateSmallUTXOs, totalAmount: %d, finalAmount: %d, selectedUtxos: %d", totalAmount, finalAmount, len(selectedUtxos))

		// Create SendOrder for selectedUtxos consolidation
		consolidationParams := &TransactionParams{
			UTXOs:          selectedUtxos,
			Withdrawals:    nil,
			Tasks:          nil,
			ChangeAddress:  p2wpkhAddress.EncodeAddress(),
			ChangeAmount:   finalAmount,
			EstimatedFee:   0,
			WitnessSize:    witnessSize,
			NetworkFee:     int64(consolidationFee),
			Net:            network,
			UtxoAmount:     totalAmount,
			WithdrawAmount: 0,
		}
		tx, actualFee, err := CreateRawTransaction(consolidationParams)
		if err != nil {
			log.Errorf("WalletServer initWithdrawSig CreateRawTransaction for consolidation error: %v", err)
			return
		}
		log.Infof("WalletServer initWithdrawSig CreateRawTransaction for consolidation, tx: %s", tx.TxID())

		msgSignSendOrder, err = w.createSendOrder(tx, db.ORDER_TYPE_CONSOLIDATION, consolidationParams.UTXOs, nil, nil, consolidationParams.UtxoAmount, actualFee, uint64(consolidationParams.NetworkFee), uint64(consolidationParams.WitnessSize), epochVoter, network)
		if err != nil {
			log.Errorf("WalletServer initWithdrawSig createSendOrder for consolidation error: %v", err)
			return
		}
	} else if tasks, err := w.state.GetSafeboxTasks(); err == nil && len(tasks) > 0 {
		selectedTasks, receiverTypes, withdrawAmount, actualPrice, err := SelectSafeboxTasks(tasks, networkFee, SAFEBOX_TASK_MAX_VOUT, SAFEBOX_TASK_IMMEDIATE_COUNT, network)
		if err != nil {
			log.Errorf("WalletServer initWithdrawSig SelectSafeboxTasks error: %v", err)
			return
		}
		if len(selectedTasks) != 1 {
			log.Infof("WalletServer initWithdrawSig no safebox tx after filter can start")
			return
		}

		// create SendOrder for selectedSafebox
		// NOTE: add external funds to cover the network fee for safebox transactions
		selectOptimalUTXOs, totalSelectedAmount, _, changeAmount, estimateFee, witnessSize, err := SelectOptimalUTXOs(utxos, receiverTypes, withdrawAmount, SAFEBOX_EXTERNAL_AMOUNT, actualPrice, len(selectedTasks))
		if err != nil {
			log.Errorf("WalletServer initWithdrawSig SelectOptimalUTXOs for safebox task error: %v", err)
			return
		}
		log.Infof("WalletServer initWithdrawSig SelectOptimalUTXOs for safebox task, totalSelectedAmount: %d, withdrawAmount: %d, changeAmount: %d, selectedUtxos: %d", totalSelectedAmount, withdrawAmount, changeAmount, len(selectOptimalUTXOs))

		// Safebox transaction
		safeboxParams := &TransactionParams{
			UTXOs:          selectOptimalUTXOs,
			Withdrawals:    nil,
			Tasks:          selectedTasks,
			ChangeAddress:  p2wpkhAddress.EncodeAddress(),
			ChangeAmount:   changeAmount,
			EstimatedFee:   estimateFee,
			WitnessSize:    witnessSize,
			NetworkFee:     actualPrice,
			Net:            network,
			UtxoAmount:     totalSelectedAmount,
			WithdrawAmount: withdrawAmount,
		}
		tx, actualFee, err := CreateRawTransaction(safeboxParams)
		if err != nil {
			log.Errorf("WalletServer initWithdrawSig CreateRawTransaction for safebox task error: %v", err)
			return
		}
		log.Infof("WalletServer initWithdrawSig CreateRawTransaction for safebox task, tx: %s", tx.TxID())

		msgSignSendOrder, err = w.createSendOrder(tx, db.ORDER_TYPE_SAFEBOX, safeboxParams.UTXOs, nil, safeboxParams.Tasks, safeboxParams.UtxoAmount, actualFee, uint64(safeboxParams.NetworkFee), uint64(safeboxParams.WitnessSize), epochVoter, network)
		if err != nil {
			log.Errorf("WalletServer initWithdrawSig createSendOrder for safebox task error: %v", err)
			return
		}
	} else {
		// 4. check withdraws can start
		withdraws, err := w.state.GetWithdrawsCanStart()
		if err != nil {
			log.Errorf("WalletServer initWithdrawSig getWithdrawsCanStart error: %v", err)
			return
		}
		if len(withdraws) == 0 {
			log.Infof("WalletServer initWithdrawSig no withdraw from db can start, count: %d", len(withdraws))
			return
		}

		selectedWithdraws, receiverTypes, withdrawAmount, actualPrice, err := SelectWithdrawals(withdraws, networkFee, WITHDRAW_MAX_VOUT, WITHDRAW_IMMEDIATE_COUNT, network)
		if err != nil {
			log.Warnf("WalletServer initWithdrawSig SelectWithdrawals error: %v", err)
			return
		}

		if len(selectedWithdraws) == 0 {
			log.Infof("WalletServer initWithdrawSig no withdraw after filter can start")
			return
		}
		// create SendOrder for selectedWithdraws
		selectOptimalUTXOs, totalSelectedAmount, _, changeAmount, estimateFee, witnessSize, err := SelectOptimalUTXOs(utxos, receiverTypes, withdrawAmount, 0, actualPrice, len(selectedWithdraws))
		if err != nil {
			log.Errorf("WalletServer initWithdrawSig SelectOptimalUTXOs for withdraw error: %v", err)
			return
		}
		log.Infof("WalletServer initWithdrawSig SelectOptimalUTXOs for withdraw, totalSelectedAmount: %d, withdrawAmount: %d, changeAmount: %d, selectedUtxos: %d", totalSelectedAmount, withdrawAmount, changeAmount, len(selectOptimalUTXOs))

		// Withdrawal transaction
		withdrawParams := &TransactionParams{
			UTXOs:          selectOptimalUTXOs,
			Withdrawals:    selectedWithdraws,
			Tasks:          nil,
			ChangeAddress:  p2wpkhAddress.EncodeAddress(),
			ChangeAmount:   changeAmount,
			EstimatedFee:   estimateFee,
			WitnessSize:    witnessSize,
			NetworkFee:     actualPrice,
			Net:            network,
			UtxoAmount:     totalSelectedAmount,
			WithdrawAmount: withdrawAmount,
		}
		tx, actualFee, err := CreateRawTransaction(withdrawParams)
		if err != nil {
			log.Errorf("WalletServer initWithdrawSig CreateRawTransaction for withdraw error: %v", err)
			if txErr, ok := err.(*TransactionError); ok && txErr.Code == ErrWithdrawDustAmount {
				// update this withdraw to closed
				for _, withdraw := range withdrawParams.Withdrawals {
					if int64(withdraw.Amount) <= types.GetDustAmount(int64(withdrawParams.NetworkFee)) {
						err = w.state.CloseWithdrawByRequestId(withdraw.RequestId, "dust limit")
					}
				}
				if err != nil {
					log.Errorf("WalletServer initWithdrawSig CloseWithdraw for dust limit withdraw error: %v", err)
				} else {
					log.Infof("WalletServer initWithdrawSig CloseWithdraw for dust limit withdraw ok, ave tx fee %d", int64(estimateFee)/int64(len(selectedWithdraws)))
				}
			}
			return
		}
		log.Infof("WalletServer initWithdrawSig CreateRawTransaction for withdraw, tx: %s, network fee rate: %d", tx.TxID(), actualPrice)

		msgSignSendOrder, err = w.createSendOrder(tx, db.ORDER_TYPE_WITHDRAWAL, withdrawParams.UTXOs, withdrawParams.Withdrawals, nil, withdrawParams.UtxoAmount, actualFee, uint64(withdrawParams.NetworkFee), uint64(withdrawParams.WitnessSize), epochVoter, network)
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
func (w *WalletServer) createSendOrder(tx *wire.MsgTx, orderType string, selectedUtxos []*db.Utxo, selectedWithdraws []*db.Withdraw, safeboxTasks []*db.SafeboxTask, utxoAmount int64, txFee, networkTxPrice, witnessSize uint64, epochVoter db.EpochVoter, network *chaincfg.Params) (*types.MsgSignSendOrder, error) {
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

	var requestId string
	if orderType == db.ORDER_TYPE_SAFEBOX {
		requestId = fmt.Sprintf("SENDORDER:TSS:%s:%s", config.AppConfig.RelayerAddress, order.OrderId)
	} else {
		requestId = fmt.Sprintf("SENDORDER:BLS:%s:%s", config.AppConfig.RelayerAddress, order.OrderId)
	}

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

	var taskIds []uint64
	var safeboxBytes []byte
	if len(safeboxTasks) > 0 {
		safeboxBytes, err = json.Marshal(safeboxTasks)
		if err != nil {
			return nil, err
		}
		for _, task := range safeboxTasks {
			taskIds = append(taskIds, task.TaskId)
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

	utxoTypes := make([]string, len(selectedUtxos))
	for i, utxo := range selectedUtxos {
		utxoTypes[i] = utxo.ReceiverType
	}

	msgSignSendOrder := &types.MsgSignSendOrder{
		MsgSign: types.MsgSign{
			RequestId:    requestId,
			Sequence:     epochVoter.Sequence,
			Epoch:        epochVoter.Epoch,
			IsProposer:   true,
			VoterAddress: epochVoter.Proposer,
			SigData:      nil,
		},
		SendOrder:   orderBytes,
		Utxos:       utxoBytes,
		Vins:        vinBytes,
		Vouts:       voutBytes,
		Withdraws:   withdrawBytes,
		WithdrawIds: withdrawIds,

		SafeboxTasks: safeboxBytes,
		TaskIds:      taskIds,

		WitnessSize: witnessSize,
	}

	// save
	err = w.state.CreateSendOrder(order, selectedUtxos, selectedWithdraws, safeboxTasks, vins, vouts, true)
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
