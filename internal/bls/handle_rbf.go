// handle_wallet.go handle wallet replace withdraw bls sig
// contains withdrawal and consolidation
package bls

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/config"
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

// handleSigStartWithdrawFinalize handle start withdraw finalize sig event
func (s *Signer) handleSigStartWithdrawReplace(ctx context.Context, e types.MsgSignReplaceWithdraw) error {
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
		return fmt.Errorf("sig replace withdraw exists: %s", e.RequestId)
	}

	// build sign
	// build sign
	newSign := &types.MsgSignReplaceWithdraw{
		MsgSign: types.MsgSign{
			RequestId:    e.RequestId,
			Sequence:     e.Sequence,
			Epoch:        e.Epoch,
			IsProposer:   true,
			VoterAddress: s.address, // proposer address
			SigData:      s.makeSigReplaceWithdraw(e.Pid, e.NewNoWitnessTx, e.NewTxFee),
			CreateTime:   time.Now().Unix(),
		},
		Pid:            e.Pid,
		NewNoWitnessTx: e.NewNoWitnessTx,
		NewTxFee:       e.NewTxFee,
	}

	// p2p broadcast
	p2pMsg := p2p.Message[any]{
		MessageType: p2p.MessageTypeSigReq,
		RequestId:   e.RequestId,
		DataType:    "MsgSignReplaceWithdraw",
		Data:        *newSign,
	}
	if err := p2p.PublishMessage(ctx, p2pMsg); err != nil {
		log.Errorf("SigStart public MsgSignReplaceWithdraw to p2p error, request id: %s, err: %v", e.RequestId, err)
		return err
	}

	return nil
}

// handleSigReceiveSendOrder handle receive replace withdraw sig event
func (s *Signer) handleSigReceiveWithdrawReplace(ctx context.Context, e types.MsgSignReplaceWithdraw) error {
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
			return fmt.Errorf("sig receive replace withdraw proposer process no sig found, request id: %s", e.RequestId)
		}
		_, ok = voteMap[e.VoterAddress]
		if ok {
			s.sigMu.Unlock()
			log.Debugf("SigReceive replace withdraw proposer process voter multi receive, request id: %s, voter address: %s", e.RequestId, e.VoterAddress)
			return nil
		}
		voteMap[e.VoterAddress] = e
		s.sigMu.Unlock()

		// UNCHECK aggregate
		msg, err := s.aggSigReplaceWithdraw(e.RequestId)
		if err != nil {
			log.Warnf("SigReceive replace withdraw proposer process aggregate sig, request id: %s, err: %v", e.RequestId, err)
			return nil
		}

		// submit to layer2
		newProposal := layer2.NewProposal[*bitcointypes.MsgReplaceWithdrawal](s.layer2Listener)
		err = newProposal.RetrySubmit(ctx, e.RequestId, msg, config.AppConfig.L2SubmitRetry)
		if err != nil {
			log.Errorf("SigReceive send withdrawal proposer submit NewBlock to RPC error, request id: %s, err: %v", e.RequestId, err)
			s.removeSigMap(e.RequestId, false)
			return err
		}

		s.removeSigMap(e.RequestId, false)

		// feedback SigFinish
		s.state.EventBus.Publish(state.SigFinish, e)

		log.Infof("SigReceive replace withdraw proposer submit NewBlock to RPC ok, request id: %s", e.RequestId)
		return nil
	} else {
		// only accept proposer msg
		if !e.IsProposer {
			return nil
		}

		// verify proposer sig
		if len(e.SigData) == 0 {
			log.Infof("SigReceive MsgSignReplaceWithdraw with empty sig data, request id %s", e.RequestId)
			return nil
		}

		// validate epoch
		if e.Epoch != epochVoter.Epoch {
			log.Warnf("SigReceive MsgSignReplaceWithdraw epoch does not match, request id %s, msg epoch: %d, current epoch: %d", e.RequestId, e.Epoch, epochVoter.Epoch)
			return fmt.Errorf("cannot handle receive sig %s with epoch %d, expect: %d", e.RequestId, e.Epoch, epochVoter.Epoch)
		}

		// build sign
		newSign := &types.MsgSignReplaceWithdraw{
			MsgSign: types.MsgSign{
				RequestId:    e.RequestId,
				Sequence:     e.Sequence,
				Epoch:        e.Epoch,
				IsProposer:   false,
				VoterAddress: s.address, // voter address
				SigData:      s.makeSigReplaceWithdraw(e.Pid, e.NewNoWitnessTx, e.NewTxFee),
				CreateTime:   time.Now().Unix(),
			},
			Pid:            e.Pid,
			NewNoWitnessTx: e.NewNoWitnessTx,
			NewTxFee:       e.NewTxFee,
		}

		// p2p broadcast
		p2pMsg := p2p.Message[any]{
			MessageType: p2p.MessageTypeSigResp,
			RequestId:   newSign.RequestId,
			DataType:    "MsgSignReplaceWithdraw",
			Data:        *newSign,
		}

		if err := p2p.PublishMessage(ctx, p2pMsg); err != nil {
			log.Errorf("SigReceive public ReplaceWithdraw to p2p error, request id: %s, err: %v", e.RequestId, err)
			return err
		}
		log.Infof("SigReceive broadcast MsgSignReplaceWithdraw ok, request id: %s", e.RequestId)
		return nil
	}
}

func (s *Signer) makeSigReplaceWithdraw(pid uint64, noWitnessTx []byte, txFee uint64) []byte {
	voters := make(bitmap.Bitmap, 5)
	votes := &relayertypes.Votes{
		Sequence:  0,
		Epoch:     0,
		Voters:    voters.ToBytes(),
		Signature: nil,
	}
	epochVoter := s.state.GetEpochVoter()
	msg := bitcointypes.MsgReplaceWithdrawal{
		Proposer:       "",
		Vote:           votes,
		Pid:            pid,
		NewNoWitnessTx: noWitnessTx,
		NewTxFee:       txFee,
	}
	sigDoc := relayertypes.VoteSignDoc(msg.MethodName(), config.AppConfig.GoatChainID, epochVoter.Proposer, epochVoter.Sequence, uint64(epochVoter.Epoch), msg.VoteSigDoc())
	return goatcryp.Sign(s.sk, sigDoc)
}

func (s *Signer) aggSigReplaceWithdraw(requestId string) (*bitcointypes.MsgReplaceWithdrawal, error) {
	epochVoter := s.state.GetEpochVoter()

	voteMap, ok := s.sigExists(requestId)
	if !ok {
		return nil, fmt.Errorf("no sig found of replace withdraw, request id: %s", requestId)
	}
	voterAll := strings.Split(epochVoter.VoteAddrList, ",")
	proposer := ""
	var txFee, epoch, sequence, pid uint64
	var noWitnessTx []byte
	var bmp bitmap.Bitmap
	var proposerSig []byte
	voteSig := make([][]byte, 0)

	for address, msg := range voteMap {
		msgReplaceWithdraw := msg.(types.MsgSignReplaceWithdraw)
		if msgReplaceWithdraw.IsProposer {
			proposer = address // proposer address
			sequence = msgReplaceWithdraw.Sequence
			epoch = msgReplaceWithdraw.Epoch
			proposerSig = msgReplaceWithdraw.SigData
			pid = msgReplaceWithdraw.Pid
			txFee = msgReplaceWithdraw.NewTxFee
			noWitnessTx = msgReplaceWithdraw.NewNoWitnessTx
		} else {
			pos := types.IndexOfSlice(voterAll, address) // voter address
			log.Debugf("Bitmap check, pos: %d, address: %s, all: %s", pos, address, epochVoter.VoteAddrList)
			if pos >= 0 {
				bmp.Set(uint32(pos))
				voteSig = append(voteSig, msgReplaceWithdraw.SigData)
			}
		}
	}

	if proposer == "" {
		return nil, fmt.Errorf("missing proposer sig msg of replace withdraw, request id: %s", requestId)
	}

	if epoch != epochVoter.Epoch {
		return nil, fmt.Errorf("incorrect epoch of replace withdraw, request id: %s, msg epoch: %d, current epoch: %d", requestId, epoch, epochVoter.Epoch)
	}
	if sequence != epochVoter.Sequence {
		return nil, fmt.Errorf("incorrect sequence of replace withdraw, request id: %s, msg sequence: %d, current sequence: %d", requestId, sequence, epochVoter.Sequence)
	}

	voteSig = append([][]byte{proposerSig}, voteSig...)

	// check threshold
	threshold := types.Threshold(len(voterAll))
	if len(voteSig) < threshold {
		return nil, fmt.Errorf("threshold not reach of replace withdraw, request id: %s, has sig: %d, threshold: %d", requestId, len(voteSig), threshold)
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

	msgReplaceWithdrawal := bitcointypes.MsgReplaceWithdrawal{
		Proposer:       proposer,
		Vote:           votes,
		Pid:            pid,
		NewNoWitnessTx: noWitnessTx,
		NewTxFee:       txFee,
	}
	return &msgReplaceWithdrawal, nil
}
