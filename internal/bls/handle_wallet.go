// handle_wallet.go handle wallet send order bls sig
// contains withdrawal and consolidation
package bls

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/layer2"
	"github.com/goatnetwork/goat-relayer/internal/p2p"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/goatnetwork/goat-relayer/internal/types"
	goatcryp "github.com/goatnetwork/goat/pkg/crypto"
	bitcointypes "github.com/goatnetwork/goat/x/bitcoin/types"
	relayertypes "github.com/goatnetwork/goat/x/relayer/types"
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
		log.Debug("Cannot unmarshal send order from msg")
		return err
	}

	// build sign
	newSign := &types.MsgSignSendOrder{
		MsgSign: types.MsgSign{
			RequestId:    e.RequestId,
			Sequence:     e.Sequence,
			Epoch:        e.Epoch,
			IsProposer:   true,
			VoterAddress: s.address, // proposer address
			SigData:      s.makeSigSendOrder(order.OrderType, e.WithdrawIds, e.WitnessSize, order.NoWitnessTx, order.TxFee),
			CreateTime:   time.Now().Unix(),
		},
		SendOrder: e.SendOrder,
		Utxos:     e.Utxos,
		Vins:      e.Vins,
		Vouts:     e.Vouts,
		Withdraws: e.Withdraws,

		WithdrawIds: e.WithdrawIds,
		WitnessSize: e.WitnessSize,
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

	// If voters count is 1, should submit soon
	msgWithdrawal, msgConsolidation, err := s.aggSigSendOrder(e.RequestId)
	if err != nil {
		log.Warnf("SigStart proposer process MsgSignSendOrder aggregate sig, request id: %s, err: %v", e.RequestId, err)
		return err
	}

	if order.OrderType == db.ORDER_TYPE_WITHDRAWAL && msgWithdrawal != nil {
		newProposal := layer2.NewProposal[*bitcointypes.MsgProcessWithdrawalV2](s.layer2Listener)
		err = newProposal.RetrySubmit(ctx, e.RequestId, msgWithdrawal, config.AppConfig.L2SubmitRetry)
		if err != nil {
			log.Errorf("SigStart proposer submit MsgSignSendOrder to RPC error, request id: %s, err: %v", e.RequestId, err)
			s.removeSigMap(e.RequestId, false)
			return err
		}
		log.Infof("SigStart proposer submit MsgSignSendOrder to RPC ok, request id: %s", e.RequestId)
	} else if msgConsolidation != nil {
		newProposal := layer2.NewProposal[*bitcointypes.MsgNewConsolidation](s.layer2Listener)
		err = newProposal.RetrySubmit(ctx, e.RequestId, msgConsolidation, config.AppConfig.L2SubmitRetry)
		if err != nil {
			log.Errorf("SigStart proposer submit MsgSignSendOrder to RPC error, request id: %s, err: %v", e.RequestId, err)
			s.removeSigMap(e.RequestId, false)
			return err
		}
		log.Infof("SigStart proposer submit MsgSignSendOrder to RPC ok, request id: %s", e.RequestId)
	}

	s.removeSigMap(e.RequestId, false)

	// feedback SigFinish
	s.state.EventBus.Publish(state.SigFinish, e)
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
				s.removeSigMap(e.RequestId, false)
				return err
			}
		} else if msgConsolidation != nil {
			newProposal := layer2.NewProposal[*bitcointypes.MsgNewConsolidation](s.layer2Listener)
			err = newProposal.RetrySubmit(ctx, e.RequestId, msgConsolidation, config.AppConfig.L2SubmitRetry)
			if err != nil {
				log.Errorf("SigReceive send consolidation proposer submit NewBlock to RPC error, request id: %s, err: %v", e.RequestId, err)
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
		err = s.state.CreateSendOrder(&order, utxos, withdraws, vins, vouts, false)
		if err != nil {
			log.Errorf("SigReceive SendOrder save to db, request id %s, err: %v", e.RequestId, err)
			return err
		}

		// build sign
		newSign := &types.MsgSignSendOrder{
			MsgSign: types.MsgSign{
				RequestId:    e.RequestId,
				Sequence:     e.Sequence,
				Epoch:        e.Epoch,
				IsProposer:   false,
				VoterAddress: s.address, // voter address
				SigData:      s.makeSigSendOrder(order.OrderType, e.WithdrawIds, e.WitnessSize, order.NoWitnessTx, order.TxFee),
				CreateTime:   time.Now().Unix(),
			},
			SendOrder: e.SendOrder,
			Utxos:     e.Utxos,
			Vins:      e.Vins,
			Vouts:     e.Vouts,
			Withdraws: e.Withdraws,

			WithdrawIds: e.WithdrawIds,
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
