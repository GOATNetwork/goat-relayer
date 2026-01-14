// handle_wallet.go handle wallet send order bls sig
// contains withdrawal and consolidation
package bls

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/layer2"
	"github.com/goatnetwork/goat-relayer/internal/p2p"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/goatnetwork/goat-relayer/internal/types"
	goatcryp "github.com/goatnetwork/goat/pkg/crypto"
	bitcointypes "github.com/goatnetwork/goat/x/bitcoin/types"
	relayertypes "github.com/goatnetwork/goat/x/relayer/types"
	tssTypes "github.com/goatnetwork/tss/pkg/types"
	"github.com/kelindar/bitmap"
	log "github.com/sirupsen/logrus"
)

// handleSigStartSendOrder handle start send order sig event
func (s *Signer) handleSigStartSendOrder(ctx context.Context, e types.MsgSignSendOrder) error {
	canSign := s.CanSign()
	isProposer := s.IsProposer()
	if !canSign || !isProposer {
		log.Debugf("Ignore SigStart SendOrder request id %s, canSign: %v, isProposer: %v", e.RequestId, canSign, isProposer)
		log.Debugf("Current l2 context, catching up: %v, self address: %s, proposer: %s", s.state.GetL2Info().Syncing, s.address, s.state.GetEpochVoter().Proposer)
		return fmt.Errorf("cannot start sig %s in current l2 context, catching up: %v, is proposer: %v", e.RequestId, !canSign, isProposer)
	}

	// request id format: SENDORDER:VoterAddr:OrderId
	// check map
	_, ok := s.sigExists(e.RequestId)
	if ok {
		return fmt.Errorf("sig send order exists: %s", e.RequestId)
	}

	var order db.SendOrder
	err := json.Unmarshal(e.SendOrder, &order)
	if err != nil {
		log.Errorf("Signer handleSigStartSendOrder - Cannot unmarshal send order from msg, request id: %s, err: %v", e.RequestId, err)
		return err
	}
	// build sign
	var sigData []byte
	var unsignTx *ethtypes.Transaction
	if e.GetSignType() == types.SIGN_TYPE_SENDORDER_TSS {
		var tasks []*db.SafeboxTask
		err := json.Unmarshal(e.SafeboxTasks, &tasks)
		if err != nil {
			log.Errorf("Signer handleSigStartSendOrder - Cannot unmarshal safebox task from msg, request id: %s, err: %v", e.RequestId, err)
			return err
		}
		if len(tasks) != 1 {
			log.Errorf("Signer handleSigStartSendOrder - Ignore, safebox task count is not 1, request id: %s", e.RequestId)
			return err
		}
		task := tasks[0]

		unsignTx, sigData, err = s.safeboxProcessor.BuildUnsignedTx(ctx, task, order.NoWitnessTx)
		if err != nil {
			log.Errorf("Signer handleSigStartSendOrder - Failed to build unsigned tx, request id: %s, err: %v", e.RequestId, err)
			return err
		}
		s.safeboxProcessor.SetTssSession(e.RequestId, task, sigData, unsignTx)
		_, err = s.safeboxProcessor.GetTssSigner().StartSign(ctx, sigData, e.RequestId)
		if err != nil {
			log.Errorf("Signer handleSigStartSendOrder - Failed to start TSS sign: %v", err)
			// reset TSS status, because TSS signing session failed to start
			s.safeboxProcessor.ResetTssAndSession(ctx)
			log.Infof("Signer handleSigStartSendOrder - Reset TSS status due to failed StartSign call")
			return err
		}
		log.Infof("Signer handleSigStartSendOrder - Start TSS sign ok, request id: %s", e.RequestId)
	} else {
		sigData = s.makeSigSendOrder(order.OrderType, e.WithdrawIds, e.WitnessSize, order.NoWitnessTx, order.TxFee)
	}

	// build sign
	newSign := &types.MsgSignSendOrder{
		MsgSign: types.MsgSign{
			RequestId:    e.RequestId,
			Sequence:     e.Sequence,
			Epoch:        e.Epoch,
			IsProposer:   true,
			VoterAddress: s.address, // proposer address
			SigData:      sigData,
			CreateTime:   e.CreateTime,
		},
		SendOrder:    e.SendOrder,
		Utxos:        e.Utxos,
		Vins:         e.Vins,
		Vouts:        e.Vouts,
		Withdraws:    e.Withdraws,
		WithdrawIds:  e.WithdrawIds,
		SafeboxTasks: e.SafeboxTasks,
		TaskIds:      e.TaskIds,
		WitnessSize:  e.WitnessSize,
	}

	// p2p broadcast
	p2pMsg := p2p.Message[any]{
		MessageType: p2p.MessageTypeSigReq,
		RequestId:   e.RequestId,
		DataType:    "MsgSignSendOrder",
		Data:        *newSign,
	}
	if err := p2p.PublishMessage(ctx, p2pMsg); err != nil {
		log.Errorf("SigStart public MsgSignSendOrder to p2p error, request id: %s, err: %v", e.RequestId, err)
		return err
	}

	s.sigMu.Lock()
	s.sigMap[e.RequestId] = make(map[string]interface{})
	s.sigMap[e.RequestId][s.address] = *newSign
	timeoutDuration := config.AppConfig.BlsSigTimeout
	s.sigTimeoutMap[e.RequestId] = time.Now().Add(timeoutDuration)
	s.sigMu.Unlock()
	log.Infof("SigStart broadcast MsgSignSendOrder ok, request id: %s", e.RequestId)

	// // If voters count is 1, should submit soon
	// msgWithdrawal, msgConsolidation, err := s.aggSigSendOrder(e.RequestId)
	// if err != nil {
	// 	log.Warnf("SigStart proposer process MsgSignSendOrder aggregate sig, request id: %s, err: %v", e.RequestId, err)
	// 	return err
	// }

	// if order.OrderType == db.ORDER_TYPE_WITHDRAWAL && msgWithdrawal != nil {
	// 	newProposal := layer2.NewProposal[*bitcointypes.MsgProcessWithdrawalV2](s.layer2Listener)
	// 	err = newProposal.RetrySubmit(ctx, e.RequestId, msgWithdrawal, config.AppConfig.L2SubmitRetry)
	// 	if err != nil {
	// 		log.Errorf("SigStart proposer submit MsgSignSendOrder to RPC error, request id: %s, err: %v", e.RequestId, err)
	// 		s.removeSigMap(e.RequestId, false)
	// 		return err
	// 	}
	// 	log.Infof("SigStart proposer submit MsgSignSendOrder to RPC ok, request id: %s", e.RequestId)
	// } else if msgConsolidation != nil {
	// 	newProposal := layer2.NewProposal[*bitcointypes.MsgNewConsolidation](s.layer2Listener)
	// 	err = newProposal.RetrySubmit(ctx, e.RequestId, msgConsolidation, config.AppConfig.L2SubmitRetry)
	// 	if err != nil {
	// 		log.Errorf("SigStart proposer submit MsgSignSendOrder to RPC error, request id: %s, err: %v", e.RequestId, err)
	// 		s.removeSigMap(e.RequestId, false)
	// 		return err
	// 	}
	// 	log.Infof("SigStart proposer submit MsgSignSendOrder to RPC ok, request id: %s", e.RequestId)
	// }

	// s.removeSigMap(e.RequestId, false)

	// feedback SigFinish
	// s.state.EventBus.Publish(state.SigFinish, e)
	return nil
}

// handleSigReceiveSendOrder handle receive send order sig event
func (s *Signer) handleSigReceiveSendOrder(ctx context.Context, e types.MsgSignSendOrder) error {
	canSign := s.CanSign()
	isProposer := s.IsProposer()
	if !canSign {
		log.Debugf("Ignore SigReceive SendOrder request id %s, canSign: %v, isProposer: %v", e.RequestId, canSign, isProposer)
		return fmt.Errorf("cannot handle receive sig %s in current l2 context, catching up: %v, is proposer: %v", e.RequestId, !canSign, isProposer)
	}

	epochVoter := s.state.GetEpochVoter()
	if isProposer {
		if e.GetSignType() == types.SIGN_TYPE_SENDORDER_TSS {
			err := s.submitSendOrderToContract(ctx, e, isProposer)
			if err != nil {
				s.removeSigMap(e.RequestId, false)
				return err
			}
		} else {
			err := s.submitSendOrderToLayer2(ctx, e, isProposer)
			if err != nil {
				s.removeSigMap(e.RequestId, false)
				return err
			}
		}

		s.removeSigMap(e.RequestId, false)

		// feedback SigFinish
		s.state.EventBus.Publish(state.SigFinish, e)

		log.Infof("SigReceive send order proposer submit NewBlock to RPC ok, request id: %s", e.RequestId)
		return nil
	} else {
		// only accept proposer msg
		if !e.IsProposer {
			return nil
		}

		// verify proposer sig
		if len(e.SigData) == 0 {
			log.Infof("SigReceive MsgSignSendOrder with empty sig data, request id %s", e.RequestId)
			return nil
		}

		// validate epoch
		if e.Epoch != epochVoter.Epoch {
			log.Warnf("SigReceive MsgSignSendOrder epoch does not match, request id %s, msg epoch: %d, current epoch: %d", e.RequestId, e.Epoch, epochVoter.Epoch)
			return fmt.Errorf("cannot handle receive sig %s with epoch %d, expect: %d", e.RequestId, e.Epoch, epochVoter.Epoch)
		}

		// extract order
		var order db.SendOrder
		var vins []*db.Vin
		var vouts []*db.Vout
		var utxos []*db.Utxo
		var withdraws []*db.Withdraw
		var safeboxTasks []*db.SafeboxTask
		var err error
		if err = json.Unmarshal(e.SendOrder, &order); err != nil {
			log.Errorf("SigReceive SendOrder request id %s unmarshal order err: %v", e.RequestId, err)
			return err
		}
		if err = json.Unmarshal(e.Vins, &vins); err != nil {
			log.Errorf("SigReceive SendOrder request id %s unmarshal vins err: %v", e.RequestId, err)
			return err
		}
		if err = json.Unmarshal(e.Vouts, &vouts); err != nil {
			log.Errorf("SigReceive SendOrder request id %s unmarshal vouts err: %v", e.RequestId, err)
			return err
		}
		if err = json.Unmarshal(e.Utxos, &utxos); err != nil {
			log.Errorf("SigReceive SendOrder request id %s unmarshal utxos err: %v", e.RequestId, err)
			return err
		}
		if order.OrderType == db.ORDER_TYPE_WITHDRAWAL {
			err = json.Unmarshal(e.Withdraws, &withdraws)
			if err != nil {
				log.Errorf("SigReceive SendOrder request id %s unmarshal withdraws err: %v", e.RequestId, err)
				return err
			}
		} else if order.OrderType == db.ORDER_TYPE_SAFEBOX {
			err = json.Unmarshal(e.SafeboxTasks, &safeboxTasks)
			if err != nil {
				log.Errorf("SigReceive SendOrder request id %s unmarshal safebox tasks err: %v", e.RequestId, err)
				return err
			}
		} else if order.OrderType == db.ORDER_TYPE_CONSOLIDATION {
			// check consolidation in init, aggregating, pending, if true, return
			if s.state.HasConsolidationInProgress() {
				log.Warnf("SigReceive SendOrder ignore, there is a consolidation in progress, request id: %s", e.RequestId)
				return fmt.Errorf("SigReceive SendOrder cannot handle, there is a consolidation in progress, request id: %s", e.RequestId)
			}
		}

		// check txid
		tx, err := types.DeserializeTransaction(order.NoWitnessTx)
		if err != nil {
			log.Errorf("SigReceive SendOrder deserialize tx, request id %s, err: %v", e.RequestId, err)
			return err
		}
		if tx.TxID() != order.Txid {
			return fmt.Errorf("SigReceive SendOrder deserialize txid %s not match order txid %s", tx.TxID(), order.Txid)
		}
		// check utxo exists
		if len(tx.TxIn) != len(vins) {
			return fmt.Errorf("SigReceive SendOrder deserialize txin len %d not match vins %d", len(tx.TxIn), len(vins))
		}
		if len(tx.TxOut) != len(vouts) {
			return fmt.Errorf("SigReceive SendOrder deserialize txout len %d not match vouts %d", len(tx.TxOut), len(vouts))
		}

		// save to local db
		err = s.state.CreateSendOrder(&order, utxos, withdraws, safeboxTasks, vins, vouts, false)
		if err != nil {
			log.Errorf("SigReceive SendOrder save to db, request id %s, err: %v", e.RequestId, err)
			return err
		}

		// build sign
		var sigData []byte
		if e.GetSignType() == types.SIGN_TYPE_SENDORDER_TSS {
			sigData = e.SigData
			if len(safeboxTasks) != 1 {
				log.Errorf("Signer handleSigReceiveSendOrder - Ignore, safebox task count is not 1, request id: %s", e.RequestId)
				return err
			}
			task := safeboxTasks[0]
			taskInDb, err := s.state.GetSafeboxTaskByTaskId(task.TaskId)
			if err != nil {
				log.Errorf("Signer handleSigReceiveSendOrder - Failed to get safebox task, request id: %s, err: %v", e.RequestId, err)
				return err
			}
			timelockAddress, witnessScript, err := types.GenerateTimeLockP2WSHAddress(taskInDb.Pubkey, time.Unix(int64(taskInDb.TimelockEndTime), 0), types.GetBTCNetwork(config.AppConfig.BTCNetworkType))
			if err != nil {
				log.Errorf("Signer handleSigReceiveSendOrder - Failed to generate timelock address, request id: %s, err: %v", e.RequestId, err)
				return err
			}
			if task.TimelockAddress != timelockAddress.EncodeAddress() || !bytes.Equal(task.WitnessScript, witnessScript) {
				log.Errorf("Signer handleSigReceiveSendOrder - Timelock details mismatch, SessionId: %s, LocalAddress: %s, RemoteAddress: %s, LocalOutIndex: %d, RemoteOutIndex: %d",
					e.RequestId, timelockAddress, task.TimelockAddress, taskInDb.TimelockOutIndex, task.TimelockOutIndex)
				return err
			}
			if task.TimelockTxid != taskInDb.TimelockTxid || task.TimelockOutIndex != taskInDb.TimelockOutIndex {
				log.Errorf("Signer handleSigReceiveSendOrder - Timelock details mismatch, SessionId: %s, LocalTxid: %s, RemoteTxid: %s, LocalOutIndex: %d, RemoteOutIndex: %d",
					e.RequestId, taskInDb.TimelockTxid, task.TimelockTxid, taskInDb.TimelockOutIndex, task.TimelockOutIndex)
				return err
			}
			s.safeboxProcessor.SetTssSession(e.RequestId, taskInDb, sigData, e.UnsignedTx)
			_, err = s.safeboxProcessor.GetTssSigner().StartSign(ctx, sigData, e.RequestId)
			if err != nil {
				log.Errorf("Signer handleSigReceiveSendOrder - Failed to start TSS sign: %v", err)
				return err
			}
			log.Infof("Signer handleSigReceiveSendOrder - Start TSS sign ok, request id: %s", e.RequestId)
		} else {
			sigData = s.makeSigSendOrder(order.OrderType, e.WithdrawIds, e.WitnessSize, order.NoWitnessTx, order.TxFee)
		}

		newSign := &types.MsgSignSendOrder{
			MsgSign: types.MsgSign{
				RequestId:    e.RequestId,
				Sequence:     e.Sequence,
				Epoch:        e.Epoch,
				IsProposer:   false,
				VoterAddress: s.address, // voter address
				SigData:      sigData,
				CreateTime:   e.CreateTime,
			},
			SendOrder:    e.SendOrder,
			Utxos:        e.Utxos,
			Vins:         e.Vins,
			Vouts:        e.Vouts,
			Withdraws:    e.Withdraws,
			WithdrawIds:  e.WithdrawIds,
			SafeboxTasks: e.SafeboxTasks,
			TaskIds:      e.TaskIds,
			WitnessSize:  e.WitnessSize,
		}

		// p2p broadcast
		p2pMsg := p2p.Message[any]{
			MessageType: p2p.MessageTypeSigResp,
			RequestId:   newSign.RequestId,
			DataType:    "MsgSignSendOrder",
			Data:        *newSign,
		}

		if err := p2p.PublishMessage(ctx, p2pMsg); err != nil {
			log.Errorf("SigReceive public SendOrder to p2p error, request id: %s, err: %v", e.RequestId, err)
			return err
		}
		log.Infof("SigReceive broadcast MsgSignSendOrder ok, request id: %s", e.RequestId)
		return nil
	}
}

func (s *Signer) makeSigSendOrder(orderType string, withdrawIds []uint64, witnessSize uint64, noWitnessTx []byte, txFee uint64) []byte {
	voters := make(bitmap.Bitmap, 5)
	votes := &relayertypes.Votes{
		Sequence:  0,
		Epoch:     0,
		Voters:    voters.ToBytes(),
		Signature: nil,
	}
	epochVoter := s.state.GetEpochVoter()
	if orderType == db.ORDER_TYPE_WITHDRAWAL {
		msg := bitcointypes.MsgProcessWithdrawalV2{
			Proposer:    "",
			Vote:        votes,
			Id:          withdrawIds,
			NoWitnessTx: noWitnessTx,
			TxFee:       txFee,
			WitnessSize: witnessSize,
		}
		sigDoc := relayertypes.VoteSignDoc(msg.MethodName(), config.AppConfig.GoatChainID, epochVoter.Proposer, epochVoter.Sequence, uint64(epochVoter.Epoch), msg.VoteSigDoc())
		return goatcryp.Sign(s.sk, sigDoc)
	} else {
		msg := bitcointypes.MsgNewConsolidation{
			Proposer:    "",
			Vote:        votes,
			NoWitnessTx: noWitnessTx,
		}
		sigDoc := relayertypes.VoteSignDoc(msg.MethodName(), config.AppConfig.GoatChainID, epochVoter.Proposer, epochVoter.Sequence, uint64(epochVoter.Epoch), msg.VoteSigDoc())
		return goatcryp.Sign(s.sk, sigDoc)
	}
}

func (s *Signer) aggSigSendOrder(requestId string) (*bitcointypes.MsgProcessWithdrawalV2, *bitcointypes.MsgNewConsolidation, error) {
	epochVoter := s.state.GetEpochVoter()

	voteMap, ok := s.sigExists(requestId)
	if !ok {
		return nil, nil, fmt.Errorf("no sig found of send order, request id: %s", requestId)
	}
	voterAll := strings.Split(epochVoter.VoteAddrList, ",")
	proposer := ""
	orderType := db.ORDER_TYPE_WITHDRAWAL
	var txFee, epoch, sequence uint64
	var noWitnessTx []byte
	var withdrawIds []uint64
	var witnessSize uint64
	var bmp bitmap.Bitmap
	var proposerSig []byte
	voteSig := make([][]byte, 0)

	for address, msg := range voteMap {
		msgSendOrder := msg.(types.MsgSignSendOrder)
		var order db.SendOrder
		err := json.Unmarshal(msgSendOrder.SendOrder, &order)
		if err != nil {
			log.Debug("Cannot unmarshal send order from vote msg")
			return nil, nil, err
		}
		if msgSendOrder.IsProposer {
			proposer = address // proposer address
			sequence = msgSendOrder.Sequence
			epoch = msgSendOrder.Epoch
			withdrawIds = msgSendOrder.WithdrawIds
			witnessSize = msgSendOrder.WitnessSize
			proposerSig = msgSendOrder.SigData

			txFee = order.TxFee
			noWitnessTx = order.NoWitnessTx
			orderType = order.OrderType
		} else {
			pos := types.IndexOfSlice(voterAll, address) // voter address
			log.Debugf("Bitmap check, pos: %d, address: %s, all: %s", pos, address, epochVoter.VoteAddrList)
			if pos >= 0 {
				bmp.Set(uint32(pos))
				voteSig = append(voteSig, msgSendOrder.SigData)
			}
		}
	}

	if proposer == "" {
		return nil, nil, fmt.Errorf("missing proposer sig msg of send order, request id: %s", requestId)
	}

	if epoch != epochVoter.Epoch {
		return nil, nil, fmt.Errorf("incorrect epoch of send order, request id: %s, msg epoch: %d, current epoch: %d", requestId, epoch, epochVoter.Epoch)
	}
	if sequence != epochVoter.Sequence {
		return nil, nil, fmt.Errorf("incorrect sequence of send order, request id: %s, msg sequence: %d, current sequence: %d", requestId, sequence, epochVoter.Sequence)
	}

	voteSig = append([][]byte{proposerSig}, voteSig...)

	// check threshold
	threshold := types.Threshold(len(voterAll))
	if len(voteSig) < threshold {
		return nil, nil, fmt.Errorf("threshold not reach of send order, request id: %s, has sig: %d, threshold: %d", requestId, len(voteSig), threshold)
	}

	// aggregate
	aggSig, err := goatcryp.AggregateSignatures(voteSig)
	if err != nil {
		return nil, nil, err
	}

	votes := &relayertypes.Votes{
		Sequence:  sequence,
		Epoch:     epoch,
		Voters:    bmp.ToBytes(),
		Signature: aggSig,
	}

	if orderType == db.ORDER_TYPE_WITHDRAWAL {
		msgWithdrawal := bitcointypes.MsgProcessWithdrawalV2{
			Proposer:    proposer,
			Vote:        votes,
			Id:          withdrawIds,
			NoWitnessTx: noWitnessTx,
			TxFee:       txFee,
			WitnessSize: witnessSize,
		}
		return &msgWithdrawal, nil, nil
	} else {
		msgConsolidation := bitcointypes.MsgNewConsolidation{
			Proposer:    proposer,
			Vote:        votes,
			NoWitnessTx: noWitnessTx,
		}
		return nil, &msgConsolidation, nil
	}
}

func (s *Signer) submitSendOrderToLayer2(ctx context.Context, e types.MsgSignSendOrder, isProposer bool) error {
	// collect voter sig
	if e.IsProposer {
		return nil
	}

	s.sigMu.Lock()
	voteMap, ok := s.sigMap[e.RequestId]
	if !ok {
		s.sigMu.Unlock()
		return fmt.Errorf("sig receive send order proposer process no sig found, request id: %s", e.RequestId)
	}
	_, ok = voteMap[e.VoterAddress]
	if ok {
		s.sigMu.Unlock()
		log.Debugf("SigReceive send order proposer process voter multi receive, request id: %s, voter address: %s", e.RequestId, e.VoterAddress)
		return nil
	}
	voteMap[e.VoterAddress] = e
	s.sigMu.Unlock()

	// UNCHECK aggregate
	msgWithdrawal, msgConsolidation, err := s.aggSigSendOrder(e.RequestId)
	if err != nil {
		log.Warnf("SigReceive send order proposer process aggregate sig, request id: %s, err: %v", e.RequestId, err)
		return nil
	}

	// withdrawal && consolidation both submit to layer2, this
	if msgWithdrawal != nil {
		newProposal := layer2.NewProposal[*bitcointypes.MsgProcessWithdrawalV2](s.layer2Listener)
		err = newProposal.RetrySubmit(ctx, e.RequestId, msgWithdrawal, config.AppConfig.L2SubmitRetry)
		if err != nil {
			log.Errorf("SigReceive send withdrawal proposer submit NewBlock to RPC error, request id: %s, err: %v", e.RequestId, err)
			return err
		}
	} else if msgConsolidation != nil {
		newProposal := layer2.NewProposal[*bitcointypes.MsgNewConsolidation](s.layer2Listener)
		err = newProposal.RetrySubmit(ctx, e.RequestId, msgConsolidation, config.AppConfig.L2SubmitRetry)
		if err != nil {
			log.Errorf("SigReceive send consolidation proposer submit NewBlock to RPC error, request id: %s, err: %v", e.RequestId, err)
			return err
		}
	}
	return nil
}

func (s *Signer) submitSendOrderToContract(ctx context.Context, e types.MsgSignSendOrder, isProposer bool) error {
	// in sign window, query tss sign status
	tssSession := s.safeboxProcessor.GetTssSession()
	if tssSession == nil {
		log.Errorf("TSS session is nil")
		return fmt.Errorf("tss session is nil")
	}

	err := s.safeboxProcessor.CheckTssStatus(ctx)
	if err != nil {
		log.Infof("SafeboxProcessor process - TSS sign status not ready, RequestId: %s, err: %v", tssSession.GetRequestId(), err)
		return err
	}

	log.Infof("SafeboxProcessor process - Querying TSS sign status, RequestId: %s", tssSession.GetRequestId())

	// retry query tss sign status
	var resp *tssTypes.EvmSignQueryResponse
	for i := 0; i <= config.AppConfig.L2SubmitRetry; i++ {
		// add 2 seconds delay
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second * 2):
		}

		resp, err = s.safeboxProcessor.GetTssSigner().QuerySignResult(ctx, tssSession.GetRequestId())
		if err != nil {
			log.Warnf("SafeboxProcessor process - Failed to query TSS sign status, attempt %d: %v, RequestId: %s", i+1, err, tssSession.GetRequestId())
			continue
		}

		if resp == nil {
			log.Warnf("SafeboxProcessor process - Query response is nil, attempt %d, RequestId: %s", i+1, tssSession.GetRequestId())
			continue
		}

		if resp.Signature == nil {
			log.Warnf("SafeboxProcessor process - No signature received yet, attempt %d, RequestId: %s", i+1, tssSession.GetRequestId())
			continue
		}

		// Only proceed with applying signature if we have a valid one
		unsignedTx := tssSession.GetUnsignedTx()
		if unsignedTx == nil {
			log.Errorf("SafeboxProcessor process - Unsigned transaction is nil, RequestId: %s", tssSession.GetRequestId())
			return fmt.Errorf("unsigned transaction is nil")
		}

		signedTx, err := s.safeboxProcessor.GetTssSigner().ApplySignResult(ctx, unsignedTx, resp.Signature)
		if err != nil {
			log.Errorf("SafeboxProcessor process - Failed to apply TSS sign result: %v, RequestId: %s", err, tssSession.GetRequestId())
			return err
		}

		// Set the signed transaction in the session
		tssSession.SetSignedTx(signedTx)

		// Submit signed tx to contract
		err = s.safeboxProcessor.SendRawTx(ctx, signedTx)
		if err != nil {
			log.Errorf("SafeboxProcessor process - Failed to send signed transaction: %v, RequestId: %s", err, tssSession.GetRequestId())
			return err
		}
	}

	if resp == nil || resp.Signature == nil {
		log.Errorf("SafeboxProcessor process - Failed to get valid signature after %d retries, RequestId: %s", config.AppConfig.L2SubmitRetry, tssSession.GetRequestId())
		return fmt.Errorf("failed to get valid signature after %d retries", config.AppConfig.L2SubmitRetry)
	}

	return nil
}

// handleSigStartRbfOrder handles the start of RBF order signature (proposer)
func (s *Signer) handleSigStartRbfOrder(ctx context.Context, e types.MsgSignRbfOrder) error {
	canSign := s.CanSign()
	isProposer := s.IsProposer()
	if !canSign || !isProposer {
		log.Debugf("Ignore SigStart RbfOrder request id %s, canSign: %v, isProposer: %v", e.RequestId, canSign, isProposer)
		return fmt.Errorf("cannot start sig %s in current l2 context, catching up: %v, is proposer: %v", e.RequestId, !canSign, isProposer)
	}

	// check if sig already exists
	_, ok := s.sigExists(e.RequestId)
	if ok {
		return fmt.Errorf("sig RBF order exists: %s", e.RequestId)
	}

	var order db.SendOrder
	err := json.Unmarshal(e.SendOrder, &order)
	if err != nil {
		log.Errorf("Signer handleSigStartRbfOrder - Cannot unmarshal send order from msg, request id: %s, err: %v", e.RequestId, err)
		return err
	}

	// Build signature for ReplaceWithdrawalV2
	sigData := s.makeSigRbfOrder(e.Pid, e.NewTxFee, e.WitnessSize, order.NoWitnessTx)

	// Build sign message
	newSign := &types.MsgSignRbfOrder{
		MsgSign: types.MsgSign{
			RequestId:    e.RequestId,
			Sequence:     e.Sequence,
			Epoch:        e.Epoch,
			IsProposer:   true,
			VoterAddress: s.address,
			SigData:      sigData,
			CreateTime:   e.CreateTime,
		},
		SendOrder:   e.SendOrder,
		Utxos:       e.Utxos,
		Vins:        e.Vins,
		Vouts:       e.Vouts,
		Pid:         e.Pid,
		WithdrawIds: e.WithdrawIds,
		NewTxFee:    e.NewTxFee,
		WitnessSize: e.WitnessSize,
	}

	// p2p broadcast
	p2pMsg := p2p.Message[any]{
		MessageType: p2p.MessageTypeSigReq,
		RequestId:   e.RequestId,
		DataType:    "MsgSignRbfOrder",
		Data:        *newSign,
	}
	if err := p2p.PublishMessage(ctx, p2pMsg); err != nil {
		log.Errorf("SigStart public MsgSignRbfOrder to p2p error, request id: %s, err: %v", e.RequestId, err)
		return err
	}

	s.sigMu.Lock()
	s.sigMap[e.RequestId] = make(map[string]interface{})
	s.sigMap[e.RequestId][s.address] = *newSign
	timeoutDuration := config.AppConfig.BlsSigTimeout
	s.sigTimeoutMap[e.RequestId] = time.Now().Add(timeoutDuration)
	s.sigMu.Unlock()
	log.Infof("SigStart broadcast MsgSignRbfOrder ok, request id: %s, Pid: %d", e.RequestId, e.Pid)

	return nil
}

// handleSigReceiveRbfOrder handles receiving RBF order signature (voter or proposer collecting)
func (s *Signer) handleSigReceiveRbfOrder(ctx context.Context, e types.MsgSignRbfOrder) error {
	canSign := s.CanSign()
	isProposer := s.IsProposer()
	if !canSign {
		log.Debugf("Ignore SigReceive RbfOrder request id %s, canSign: %v, isProposer: %v", e.RequestId, canSign, isProposer)
		return fmt.Errorf("cannot handle receive sig %s in current l2 context, catching up: %v, is proposer: %v", e.RequestId, !canSign, isProposer)
	}

	epochVoter := s.state.GetEpochVoter()
	if isProposer {
		// Proposer collects signatures and submits to chain
		err := s.submitRbfOrderToLayer2(ctx, e)
		if err != nil {
			s.removeSigMap(e.RequestId, false)
			return err
		}

		s.removeSigMap(e.RequestId, false)

		// feedback SigFinish
		s.state.EventBus.Publish(state.SigFinish, e)

		log.Infof("SigReceive RBF order proposer submit ReplaceWithdrawalV2 to RPC ok, request id: %s", e.RequestId)
		return nil
	} else {
		// Voter: only accept proposer msg
		if !e.IsProposer {
			return nil
		}

		// verify proposer sig
		if len(e.SigData) == 0 {
			log.Infof("SigReceive MsgSignRbfOrder with empty sig data, request id %s", e.RequestId)
			return nil
		}

		// validate epoch
		if e.Epoch != epochVoter.Epoch {
			log.Warnf("SigReceive MsgSignRbfOrder epoch does not match, request id %s, msg epoch: %d, current epoch: %d", e.RequestId, e.Epoch, epochVoter.Epoch)
			return fmt.Errorf("cannot handle receive sig %s with epoch %d, expect: %d", e.RequestId, e.Epoch, epochVoter.Epoch)
		}

		// Extract order
		var order db.SendOrder
		var vins []*db.Vin
		var vouts []*db.Vout
		var utxos []*db.Utxo
		var err error
		if err = json.Unmarshal(e.SendOrder, &order); err != nil {
			log.Errorf("SigReceive RbfOrder request id %s unmarshal order err: %v", e.RequestId, err)
			return err
		}
		if err = json.Unmarshal(e.Vins, &vins); err != nil {
			log.Errorf("SigReceive RbfOrder request id %s unmarshal vins err: %v", e.RequestId, err)
			return err
		}
		if err = json.Unmarshal(e.Vouts, &vouts); err != nil {
			log.Errorf("SigReceive RbfOrder request id %s unmarshal vouts err: %v", e.RequestId, err)
			return err
		}
		if err = json.Unmarshal(e.Utxos, &utxos); err != nil {
			log.Errorf("SigReceive RbfOrder request id %s unmarshal utxos err: %v", e.RequestId, err)
			return err
		}

		// check txid
		tx, err := types.DeserializeTransaction(order.NoWitnessTx)
		if err != nil {
			log.Errorf("SigReceive RbfOrder deserialize tx, request id %s, err: %v", e.RequestId, err)
			return err
		}
		if tx.TxID() != order.Txid {
			return fmt.Errorf("SigReceive RbfOrder deserialize txid %s not match order txid %s", tx.TxID(), order.Txid)
		}

		// Build signature for ReplaceWithdrawalV2
		sigData := s.makeSigRbfOrder(e.Pid, e.NewTxFee, e.WitnessSize, order.NoWitnessTx)

		newSign := &types.MsgSignRbfOrder{
			MsgSign: types.MsgSign{
				RequestId:    e.RequestId,
				Sequence:     e.Sequence,
				Epoch:        e.Epoch,
				IsProposer:   false,
				VoterAddress: s.address,
				SigData:      sigData,
				CreateTime:   e.CreateTime,
			},
			SendOrder:   e.SendOrder,
			Utxos:       e.Utxos,
			Vins:        e.Vins,
			Vouts:       e.Vouts,
			Pid:         e.Pid,
			WithdrawIds: e.WithdrawIds,
			NewTxFee:    e.NewTxFee,
			WitnessSize: e.WitnessSize,
		}

		// p2p broadcast
		p2pMsg := p2p.Message[any]{
			MessageType: p2p.MessageTypeSigResp,
			RequestId:   newSign.RequestId,
			DataType:    "MsgSignRbfOrder",
			Data:        *newSign,
		}

		if err := p2p.PublishMessage(ctx, p2pMsg); err != nil {
			log.Errorf("SigReceive public RbfOrder to p2p error, request id: %s, err: %v", e.RequestId, err)
			return err
		}
		log.Infof("SigReceive broadcast MsgSignRbfOrder ok, request id: %s", e.RequestId)
		return nil
	}
}

// makeSigRbfOrder creates the BLS signature for MsgReplaceWithdrawalV2
func (s *Signer) makeSigRbfOrder(pid, newTxFee, witnessSize uint64, noWitnessTx []byte) []byte {
	voters := make(bitmap.Bitmap, 5)
	votes := &relayertypes.Votes{
		Sequence:  0,
		Epoch:     0,
		Voters:    voters.ToBytes(),
		Signature: nil,
	}
	epochVoter := s.state.GetEpochVoter()

	msg := bitcointypes.MsgReplaceWithdrawalV2{
		Proposer:       "",
		Vote:           votes,
		Pid:            pid,
		NewNoWitnessTx: noWitnessTx,
		NewTxFee:       newTxFee,
		WitnessSize:    witnessSize,
	}
	sigDoc := relayertypes.VoteSignDoc(msg.MethodName(), config.AppConfig.GoatChainID, epochVoter.Proposer, epochVoter.Sequence, uint64(epochVoter.Epoch), msg.VoteSigDoc())
	return goatcryp.Sign(s.sk, sigDoc)
}

// aggSigRbfOrder aggregates signatures for RBF order
func (s *Signer) aggSigRbfOrder(requestId string) (*bitcointypes.MsgReplaceWithdrawalV2, error) {
	epochVoter := s.state.GetEpochVoter()

	voteMap, ok := s.sigExists(requestId)
	if !ok {
		return nil, fmt.Errorf("no sig found of RBF order, request id: %s", requestId)
	}
	voterAll := strings.Split(epochVoter.VoteAddrList, ",")
	proposer := ""
	var pid, newTxFee, witnessSize, epoch, sequence uint64
	var noWitnessTx []byte
	var bmp bitmap.Bitmap
	var proposerSig []byte
	voteSig := make([][]byte, 0)

	for address, msg := range voteMap {
		msgRbfOrder := msg.(types.MsgSignRbfOrder)
		var order db.SendOrder
		err := json.Unmarshal(msgRbfOrder.SendOrder, &order)
		if err != nil {
			log.Debug("Cannot unmarshal RBF order from vote msg")
			return nil, err
		}
		if msgRbfOrder.IsProposer {
			proposer = address
			sequence = msgRbfOrder.Sequence
			epoch = msgRbfOrder.Epoch
			pid = msgRbfOrder.Pid
			newTxFee = msgRbfOrder.NewTxFee
			witnessSize = msgRbfOrder.WitnessSize
			proposerSig = msgRbfOrder.SigData
			noWitnessTx = order.NoWitnessTx
		} else {
			pos := types.IndexOfSlice(voterAll, address)
			log.Debugf("Bitmap check, pos: %d, address: %s, all: %s", pos, address, epochVoter.VoteAddrList)
			if pos >= 0 {
				bmp.Set(uint32(pos))
				voteSig = append(voteSig, msgRbfOrder.SigData)
			}
		}
	}

	if proposer == "" {
		return nil, fmt.Errorf("missing proposer sig msg of RBF order, request id: %s", requestId)
	}

	if epoch != epochVoter.Epoch {
		return nil, fmt.Errorf("incorrect epoch of RBF order, request id: %s, msg epoch: %d, current epoch: %d", requestId, epoch, epochVoter.Epoch)
	}
	if sequence != epochVoter.Sequence {
		return nil, fmt.Errorf("incorrect sequence of RBF order, request id: %s, msg sequence: %d, current sequence: %d", requestId, sequence, epochVoter.Sequence)
	}

	voteSig = append([][]byte{proposerSig}, voteSig...)

	// check threshold
	threshold := types.Threshold(len(voterAll))
	if len(voteSig) < threshold {
		return nil, fmt.Errorf("threshold not reach of RBF order, request id: %s, has sig: %d, threshold: %d", requestId, len(voteSig), threshold)
	}

	// aggregate
	aggSig, err := goatcryp.AggregateSignatures(voteSig)
	if err != nil {
		return nil, err
	}

	votes := &relayertypes.Votes{
		Sequence:  sequence,
		Epoch:     epoch,
		Voters:    bmp.ToBytes(),
		Signature: aggSig,
	}

	msgReplaceWithdrawal := bitcointypes.MsgReplaceWithdrawalV2{
		Proposer:       proposer,
		Vote:           votes,
		Pid:            pid,
		NewNoWitnessTx: noWitnessTx,
		NewTxFee:       newTxFee,
		WitnessSize:    witnessSize,
	}
	return &msgReplaceWithdrawal, nil
}

func (s *Signer) submitRbfOrderToLayer2(ctx context.Context, e types.MsgSignRbfOrder) error {
	// collect voter sig
	if e.IsProposer {
		return nil
	}

	s.sigMu.Lock()
	voteMap, ok := s.sigMap[e.RequestId]
	if !ok {
		s.sigMu.Unlock()
		return fmt.Errorf("sig receive RBF order proposer process no sig found, request id: %s", e.RequestId)
	}
	_, ok = voteMap[e.VoterAddress]
	if ok {
		s.sigMu.Unlock()
		log.Debugf("SigReceive RBF order proposer process voter multi receive, request id: %s, voter address: %s", e.RequestId, e.VoterAddress)
		return nil
	}
	voteMap[e.VoterAddress] = e
	s.sigMu.Unlock()

	// aggregate signatures
	msgReplaceWithdrawal, err := s.aggSigRbfOrder(e.RequestId)
	if err != nil {
		log.Warnf("SigReceive RBF order proposer process aggregate sig, request id: %s, err: %v", e.RequestId, err)
		return nil
	}

	// submit to layer2
	if msgReplaceWithdrawal != nil {
		newProposal := layer2.NewProposal[*bitcointypes.MsgReplaceWithdrawalV2](s.layer2Listener)
		err = newProposal.RetrySubmit(ctx, e.RequestId, msgReplaceWithdrawal, config.AppConfig.L2SubmitRetry)
		if err != nil {
			log.Errorf("SigReceive RBF order proposer submit ReplaceWithdrawalV2 to RPC error, request id: %s, err: %v", e.RequestId, err)
			return err
		}
		log.Infof("SigReceive RBF order proposer submit ReplaceWithdrawalV2 to RPC ok, request id: %s, Pid: %d", e.RequestId, msgReplaceWithdrawal.Pid)
	}
	return nil
}
