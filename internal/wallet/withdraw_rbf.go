package wallet

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/goatnetwork/goat-relayer/internal/types"
	log "github.com/sirupsen/logrus"
)

func (w *WalletServer) replaceWithdrawSig() {
	log.Debug("WalletServer replaceWithdrawSig")

	// 1. check catching up, self is proposer
	l2Info := w.state.GetL2Info()
	if l2Info.Syncing {
		log.Infof("WalletServer replaceWithdrawSig ignore, layer2 is catching up")
		return
	}

	btcState := w.state.GetBtcHead()
	if btcState.Syncing {
		log.Infof("WalletServer replaceWithdrawSig ignore, btc is catching up")
		return
	}

	w.sigMu.Lock()
	defer w.sigMu.Unlock()

	epochVoter := w.state.GetEpochVoter()
	if epochVoter.Proposer != config.AppConfig.RelayerAddress {
		// do not clean immediately
		if w.replaceWithdrawStatus && l2Info.Height > epochVoter.Height+1 {
			w.replaceWithdrawStatus = false
			// clean process, role changed, remove all status "create", "aggregating"
		}
		log.Debugf("WalletServer replaceWithdrawSig ignore, self is not proposer, epoch: %d, proposer: %s", epochVoter.Epoch, epochVoter.Proposer)
		return
	}

	// 2. check if there is a sig in progress
	if w.replaceWithdrawStatus {
		log.Debug("WalletServer replaceWithdrawSig ignore, there is replace in progress")
		return
	}
	if l2Info.Height <= w.replaceWithdrawFinishHeight+2 {
		log.Debug("WalletServer replaceWithdrawSig ignore, last finish replace in 2 blocks")
		return
	}

	withdraw, err := w.state.GetWithdrawsNeedRbf()
	if err != nil {
		log.Errorf("WalletServer replaceWithdrawSig GetWithdrawsNeedRbf error: %v", err)
		return
	}

	sendOrder, err := w.state.GetSendOrderByTxIdOrExternalId(withdraw.Txid)
	if err != nil {
		log.Errorf("WalletServer replaceWithdrawSig GetSendOrderByTxIdOrExternalId error: %v, withdraw: %v", err, withdraw)
		return
	}
	if sendOrder.OrderType == db.ORDER_TYPE_CONSOLIDATION {
		log.Debugf("WalletServer replaceWithdrawSig ignore, order type is consolidation, withdraw: %v", withdraw)
		return
	}

	oldTx, err := types.DeserializeTransaction(sendOrder.NoWitnessTx)
	if err != nil {
		log.Errorf("WalletServer replaceWithdrawSig DeserializeTransaction error: %v, withdraw: %v", err, withdraw)
		return
	}

	lastTxPrices := strings.Split(withdraw.LastTxPrice, ",")
	if len(lastTxPrices) == 0 {
		log.Errorf("WalletServer replaceWithdrawSig lastTxPrices is empty, withdraw: %v", withdraw)
		return
	}
	lastTxPrice := lastTxPrices[len(lastTxPrices)-1]
	lastTxPriceUint, err := strconv.ParseUint(lastTxPrice, 10, 64)
	if err != nil {
		log.Errorf("WalletServer replaceWithdrawSig ParseUint error: %v, lastTxPrice: %v", err, lastTxPrice)
		return
	}

	// Calculate old fee
	var oldTxBuf bytes.Buffer
	err = oldTx.Serialize(&oldTxBuf)
	if err != nil {
		log.Errorf("WalletServer replaceWithdrawSig serialize oldTx error: %v", err)
		return
	}
	oldTxSize := uint64(len(oldTxBuf.Bytes()))
	oldFee := lastTxPriceUint * oldTxSize

	// Find target output
	addr, err := btcutil.DecodeAddress(withdraw.To, types.GetBTCNetwork(config.AppConfig.BTCNetworkType))
	if err != nil {
		log.Errorf("WalletServer replaceWithdrawSig DecodeAddress error: %v, withdraw: %v", err, withdraw)
		return
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		log.Errorf("WalletServer replaceWithdrawSig PayToAddrScript error: %v", err)
		return
	}

	var targetVout *wire.TxOut
	var targetIndex int
	for i, vout := range oldTx.TxOut {
		if bytes.Equal(pkScript, vout.PkScript) {
			targetVout = vout
			targetIndex = i
			break
		}
	}

	if targetVout == nil {
		log.Errorf("WalletServer replaceWithdrawSig cannot find target output for withdraw: %v", withdraw)
		return
	}

	// Calculate expected new fee
	expectedNewFee := withdraw.TxPrice * oldTxSize
	feeDiff := expectedNewFee - oldFee

	// Validate if new fee is reasonable
	if feeDiff <= 0 {
		log.Debugf("WalletServer replaceWithdrawSig new fee not higher than old fee: new %d, old %d", expectedNewFee, oldFee)
		return
	}

	// Validate if new amount is reasonable
	newAmount := targetVout.Value - int64(feeDiff)
	if newAmount <= 0 {
		log.Errorf("WalletServer replaceWithdrawSig new amount too small: %d, old amount: %d, fee diff: %d",
			newAmount, targetVout.Value, feeDiff)
		return
	}

	// Create new transaction
	newTx := &wire.MsgTx{
		Version:  oldTx.Version,
		TxIn:     oldTx.TxIn,
		LockTime: oldTx.LockTime,
	}

	// Copy all outputs and update target output amount
	for i, vout := range oldTx.TxOut {
		newVout := &wire.TxOut{
			PkScript: vout.PkScript,
			Value:    vout.Value,
		}
		if i == targetIndex {
			newVout.Value = newAmount
		}
		newTx.TxOut = append(newTx.TxOut, newVout)
	}

	// Validate new transaction size
	var newTxBuf bytes.Buffer
	err = newTx.Serialize(&newTxBuf)
	if err != nil {
		log.Errorf("WalletServer replaceWithdrawSig serialize newTx error: %v", err)
		return
	}
	newTxSize := uint64(len(newTxBuf.Bytes()))
	actualNewFee := withdraw.TxPrice * newTxSize

	log.Debugf("WalletServer replaceWithdrawSig fee details: old_size=%d, new_size=%d, old_fee=%d, expected_new_fee=%d, actual_new_fee=%d",
		oldTxSize, newTxSize, oldFee, expectedNewFee, actualNewFee)

	// Serialize new transaction
	newNoWitnessTx, err := types.SerializeTransaction(newTx)
	if err != nil {
		log.Errorf("WalletServer replaceWithdrawSig SerializeTransaction error: %v", err)
		return
	}

	requestId := fmt.Sprintf("WITHDRAWRBF:%s:%d", config.AppConfig.RelayerAddress, withdraw.RequestId)
	msgSignReplace := types.MsgSignReplaceWithdraw{
		MsgSign: types.MsgSign{
			RequestId:    requestId,
			VoterAddress: epochVoter.Proposer,
		},
		Pid:            sendOrder.Pid,
		NewNoWitnessTx: newNoWitnessTx,
		NewTxFee:       actualNewFee,
	}
	w.state.EventBus.Publish(state.SigStart, msgSignReplace)
	w.replaceWithdrawStatus = true
	log.Infof("P2P publish msgSignReplace success, request id: %s", requestId)
}
