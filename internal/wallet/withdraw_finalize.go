package wallet

import (
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/goatnetwork/goat-relayer/internal/types"
	log "github.com/sirupsen/logrus"
)

func (w *WalletServer) finalizeWithdrawSig() {
	log.Debug("WalletServer finalizeWithdrawSig")

	// 1. check catching up, self is proposer
	l2Info := w.state.GetL2Info()
	if l2Info.Syncing {
		log.Infof("WalletServer finalizeWithdrawSig ignore, layer2 is catching up")
		return
	}

	btcState := w.state.GetBtcHead()
	if btcState.Syncing {
		log.Infof("WalletServer finalizeWithdrawSig ignore, btc is catching up")
		return
	}

	w.finalizeWithdrawMu.Lock()
	defer w.finalizeWithdrawMu.Unlock()

	epochVoter := w.state.GetEpochVoter()
	if epochVoter.Proposer != config.AppConfig.RelayerAddress {
		// do not clean immediately
		if w.finalizeWithdrawStatus && l2Info.Height > epochVoter.Height+1 {
			w.finalizeWithdrawStatus = false
			// clean process, role changed, remove all status "create", "aggregating"
		}
		log.Debugf("WalletServer finalizeWithdrawSig ignore, self is not proposer, epoch: %d, proposer: %s", epochVoter.Epoch, epochVoter.Proposer)
		return
	}

	// 2. check if there is a sig in progress
	if w.finalizeWithdrawStatus {
		log.Debug("WalletServer finalizeWithdrawSig ignore, there is finalize in progress")
		return
	}
	if l2Info.Height <= w.finalizeWithdrawFinishHeight+2 {
		log.Debug("WalletServer finalizeWithdrawSig ignore, last finish finalize in 2 blocks")
		return
	}

	sendOrder, err := w.state.GetLatestSendOrderConfirmed()
	if err != nil || sendOrder == nil {
		log.Errorf("WalletServer finalizeWithdrawSig get latest confirmed send order error: %v", err)
		return
	}

	if sendOrder.Txid == "" {
		log.Infof("WalletServer finalizeWithdrawSig no confirmed send order")
		return
	}
	log.Debugf("WalletServer finalizeWithdrawSig get latest confirmed send order, sendOrder: %+v", sendOrder)

	btcBlockData, err := w.state.QueryBtcBlockDataByHeight(sendOrder.BtcBlock)
	if err != nil {
		log.Errorf("WalletServer finalizeWithdrawSig query btc block data by height error: %v", err)
		return
	}
	txhash, err := chainhash.NewHashFromStr(sendOrder.Txid)
	if err != nil {
		log.Errorf("WalletServer finalizeWithdrawSig new hash from str error: %v", err)
		return
	}
	txHashes := make([]string, 0)
	err = json.Unmarshal([]byte(btcBlockData.TxHashes), &txHashes)
	if err != nil {
		return
	}
	_, proof, txIndex, err := types.GenerateSPVProof(sendOrder.Txid, txHashes)
	if err != nil {
		log.Errorf("WalletServer finalizeWithdrawSig generate spv proof error: %v", err)
		return
	}
	requestId := fmt.Sprintf("WITHDRAWFINALIZE:%s:%d", config.AppConfig.RelayerAddress, sendOrder.BtcBlock)
	msgSignFinalize := types.MsgSignFinalizeWithdraw{
		MsgSign: types.MsgSign{
			RequestId:    requestId,
			VoterAddress: epochVoter.Proposer,
		},
		Txid:              txhash.CloneBytes(),
		BlockNumber:       uint64(sendOrder.BtcBlock),
		TxIndex:           uint32(txIndex),
		IntermediateProof: proof,
		BlockHeader:       btcBlockData.Header,
	}
	w.state.EventBus.Publish(state.SigStart, msgSignFinalize)
	w.finalizeWithdrawStatus = true
	log.Infof("P2P publish msgSignFinalize success, request id: %s", requestId)
}
