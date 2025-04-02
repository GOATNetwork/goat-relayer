package layer2

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/txscript"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/types"
	bitcointypes "github.com/goatnetwork/goat/x/bitcoin/types"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

func (lis *Layer2Listener) processMsgInitializeWithdrawal(msg *bitcointypes.MsgProcessWithdrawalV2) error {
	log.Debugf("Process MsgInitializeWithdrawal, no witness tx: %v, tx fee: %d, withdraw ids: %v", msg.NoWitnessTx, msg.TxFee, msg.Id)
	network := types.GetBTCNetwork(config.AppConfig.BTCNetworkType)
	tx, err := types.DeserializeTransaction(msg.NoWitnessTx)
	if err != nil {
		return fmt.Errorf("failed to deserialize transaction: %v", err)
	}

	orderId := uuid.New().String()
	utxoAmount := int64(msg.TxFee)

	var vins []*db.Vin
	for _, txIn := range tx.TxIn {
		vin := &db.Vin{
			OrderId:      orderId,
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
			return err
		}
		withdrawId := ""
		if len(msg.Id) > i {
			withdrawId = fmt.Sprintf("%d", msg.Id[i])
		}
		vout := &db.Vout{
			OrderId:    orderId,
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

	order := &db.SendOrder{
		OrderId:     orderId,
		Proposer:    msg.Proposer,
		Amount:      uint64(utxoAmount),
		TxPrice:     0, // recover mode set to 0
		Status:      db.ORDER_STATUS_INIT,
		OrderType:   db.ORDER_TYPE_WITHDRAWAL,
		BtcBlock:    0,
		Txid:        tx.TxID(),
		NoWitnessTx: msg.NoWitnessTx,
		TxFee:       msg.TxFee,
		UpdatedAt:   time.Now(),
	}

	return lis.state.RecoverSendOrder(order, vins, vouts, msg.Id)
}
