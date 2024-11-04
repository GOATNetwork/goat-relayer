// handle_block.go handle btc new block bls sig
package bls

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/p2p"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/goatnetwork/goat-relayer/internal/types"
	goatcryp "github.com/goatnetwork/goat/pkg/crypto"
	bitcointypes "github.com/goatnetwork/goat/x/bitcoin/types"
	relayertypes "github.com/goatnetwork/goat/x/relayer/types"
	"github.com/kelindar/bitmap"
	log "github.com/sirupsen/logrus"
)

func (s *Signer) handleSigStartNewBlock(ctx context.Context, e types.MsgSignNewBlock) error {
	canSign := s.CanSign()
	isProposer := s.IsProposer()
	if !canSign || !isProposer {
		log.Debugf("Ignore SigStart request id %s, canSign: %v, isProposer: %v", e.RequestId, canSign, isProposer)
		log.Debugf("Current l2 context, catching up: %v, self address: %s, proposer: %s", s.state.GetL2Info().Syncing, s.address, s.state.GetEpochVoter().Proposer)
		return fmt.Errorf("cannot start sig %s in current l2 context, catching up: %v, is proposer: %v", e.RequestId, !canSign, isProposer)
	}

	expectStartHeight := s.state.GetL2Info().LatestBtcHeight + 1
	if expectStartHeight != e.StartBlockNumber {
		return fmt.Errorf("cannot start sig %s with start block number %d, expect: %d", e.RequestId, e.StartBlockNumber, expectStartHeight)
	}

	// request id format: BtcHead:VoterAddr:StartBlockNumber
	// check map
	_, ok := s.sigExists(e.RequestId)
	if ok {
		return fmt.Errorf("sig exists: %s", e.RequestId)
	}

	// build sign
	newSign := &types.MsgSignNewBlock{
		MsgSign: types.MsgSign{
			RequestId:    e.RequestId,
			Sequence:     e.Sequence,
			Epoch:        e.Epoch,
			IsProposer:   true,
			VoterAddress: s.address, // proposer address
			SigData:      s.makeSigNewBlock(e.StartBlockNumber, e.BlockHash),
			CreateTime:   time.Now().Unix(),
		},
		StartBlockNumber: e.StartBlockNumber,
		BlockHash:        e.BlockHash,
	}

	// p2p broadcast
	p2pMsg := p2p.Message[any]{
		MessageType: p2p.MessageTypeSigReq,
		RequestId:   e.RequestId,
		DataType:    "MsgSignNewBlock",
		Data:        *newSign,
	}
	if err := p2p.PublishMessage(ctx, p2pMsg); err != nil {
		log.Errorf("SigStart public NewBlock to p2p error, request id: %s, err: %v", e.RequestId, err)
		return err
	}

	s.sigMu.Lock()
	s.sigMap[e.RequestId] = make(map[string]interface{})
	s.sigMap[e.RequestId][s.address] = *newSign
	timeoutDuration := config.AppConfig.BlsSigTimeout
	s.sigTimeoutMap[e.RequestId] = time.Now().Add(timeoutDuration)
	s.sigMu.Unlock()
	log.Infof("SigStart broadcast ok, request id: %s", e.RequestId)

	// If voters count is 1, should submit soon
	// UNCHECK aggregate
	rpcMsg, err := s.aggSigNewBlock(e.RequestId)
	if err != nil {
		log.Warnf("SigStart proposer process aggregate sig, request id: %s, err: %v", e.RequestId, err)
		return nil
	}

	err = s.RetrySubmit(ctx, e.RequestId, rpcMsg, config.AppConfig.L2SubmitRetry)
	if err != nil {
		log.Errorf("SigStart proposer submit NewBlock to RPC error, request id: %s, err: %v", e.RequestId, err)
		s.removeSigMap(e.RequestId, false)
		return err
	}

	s.removeSigMap(e.RequestId, false)

	// feedback SigFinish
	s.state.EventBus.Publish(state.SigFinish, e)

	log.Infof("SigStart proposer submit NewBlock to RPC ok, request id: %s", e.RequestId)
	return nil
}

func (s *Signer) handleSigReceiveNewBlock(ctx context.Context, e types.MsgSignNewBlock) error {
	canSign := s.CanSign()
	isProposer := s.IsProposer()
	if !canSign {
		log.Debugf("Ignore SigReceive request id %s, canSign: %v, isProposer: %v", e.RequestId, canSign, isProposer)
		return fmt.Errorf("cannot handle receive sig %s in current l2 context, catching up: %v, is proposer: %v", e.RequestId, !canSign, isProposer)
	}

	epochVoter := s.state.GetEpochVoter()
	l2Info := s.state.GetL2Info()
	if isProposer {
		// collect voter sig
		if e.IsProposer {
			return nil
		}

		s.sigMu.Lock()
		voteMap, ok := s.sigMap[e.RequestId]
		if !ok {
			s.sigMu.Unlock()
			return fmt.Errorf("sig receive proposer process no sig found, request id: %s", e.RequestId)
		}
		_, ok = voteMap[e.VoterAddress]
		if ok {
			s.sigMu.Unlock()
			log.Debugf("SigReceive proposer process voter multi receive, request id: %s, voter address: %s", e.RequestId, e.VoterAddress)
			return nil
		}
		voteMap[e.VoterAddress] = e
		s.sigMu.Unlock()

		// UNCHECK aggregate
		rpcMsg, err := s.aggSigNewBlock(e.RequestId)
		if err != nil {
			log.Warnf("SigReceive proposer process aggregate sig, request id: %s, err: %v", e.RequestId, err)
			return nil
		}

		err = s.RetrySubmit(ctx, e.RequestId, rpcMsg, config.AppConfig.L2SubmitRetry)
		if err != nil {
			log.Errorf("SigReceive proposer submit NewBlock to RPC error, request id: %s, err: %v", e.RequestId, err)
			s.removeSigMap(e.RequestId, false)
			return err
		}

		s.removeSigMap(e.RequestId, false)

		// feedback SigFinish
		s.state.EventBus.Publish(state.SigFinish, e)

		log.Infof("SigReceive proposer submit NewBlock to RPC ok, request id: %s", e.RequestId)
		return nil
	} else {
		if !e.IsProposer {
			return nil
		}

		// validate startBlockNumber, hashs local
		expectStartHeight := l2Info.LatestBtcHeight + 1
		if expectStartHeight != e.StartBlockNumber {
			log.Warnf("SigReceive MsgSignNewBlock StartBlockNumber does not match LatestBtcHeight, request id %s, StartBlockNumber: %d, LatestBtcHeight plus 1: %d", e.RequestId, e.StartBlockNumber, l2Info.LatestBtcHeight+1)
			return fmt.Errorf("cannot handle receive sig %s with start block number %d, expect: %d", e.RequestId, e.StartBlockNumber, expectStartHeight)
		}
		// validate epoch
		if e.Epoch != epochVoter.Epoch {
			log.Warnf("SigReceive MsgSignNewBlock epoch does not match, request id %s, msg epoch: %d, current epoch: %d", e.RequestId, e.Epoch, epochVoter.Epoch)
			return fmt.Errorf("cannot handle receive sig %s with epoch %d, expect: %d", e.RequestId, e.Epoch, epochVoter.Epoch)
		}
		// TODO hash comparation

		newSign := &types.MsgSignNewBlock{
			MsgSign: types.MsgSign{
				RequestId:    e.RequestId,
				Sequence:     e.Sequence,
				Epoch:        e.Epoch,
				IsProposer:   false,
				VoterAddress: s.address, // voter address
				SigData:      s.makeSigNewBlock(e.StartBlockNumber, e.BlockHash),
				CreateTime:   time.Now().Unix(),
			},
			StartBlockNumber: e.StartBlockNumber,
			BlockHash:        e.BlockHash,
		}
		// p2p broadcast
		p2pMsg := p2p.Message[any]{
			MessageType: p2p.MessageTypeSigResp,
			RequestId:   newSign.RequestId,
			DataType:    "MsgSignNewBlock",
			Data:        *newSign,
		}

		if err := p2p.PublishMessage(ctx, p2pMsg); err != nil {
			log.Errorf("SigReceive public MsgSignNewBlock to p2p error, request id: %s, err: %v", e.RequestId, err)
			return err
		}
		log.Infof("SigReceive broadcast MsgSignNewBlock ok, request id: %s", e.RequestId)
		return nil
	}
}

func (s *Signer) makeSigNewBlock(startBlockNumber uint64, hashs [][]byte) []byte {
	voters := make(bitmap.Bitmap, 5)
	votes := &relayertypes.Votes{
		Sequence:  0,
		Epoch:     0,
		Voters:    voters.ToBytes(),
		Signature: nil,
	}
	msgBlock := bitcointypes.MsgNewBlockHashes{
		Proposer:         "",
		Vote:             votes,
		StartBlockNumber: startBlockNumber,
		BlockHash:        hashs,
	}

	epochVoter := s.state.GetEpochVoter()
	sigDoc := relayertypes.VoteSignDoc(msgBlock.MethodName(), config.AppConfig.GoatChainID, epochVoter.Proposer, epochVoter.Sequence, uint64(epochVoter.Epoch), msgBlock.VoteSigDoc())
	return goatcryp.Sign(s.sk, sigDoc)
}

func (s *Signer) aggSigNewBlock(requestId string) (*bitcointypes.MsgNewBlockHashes, error) {
	epochVoter := s.state.GetEpochVoter()

	voteMap, ok := s.sigExists(requestId)
	if !ok {
		return nil, fmt.Errorf("no sig found, request id: %s", requestId)
	}
	voterAll := strings.Split(epochVoter.VoteAddrList, ",")
	proposer := ""
	var startBlockNumber, epoch, sequence uint64
	var hashs [][]byte
	var bmp bitmap.Bitmap
	var proposerSig []byte
	voteSig := make([][]byte, 0)

	for address, msg := range voteMap {
		msgNewBlock := msg.(types.MsgSignNewBlock)
		if msgNewBlock.IsProposer {
			proposer = address // proposer address
			sequence = msgNewBlock.Sequence
			epoch = msgNewBlock.Epoch
			startBlockNumber = msgNewBlock.StartBlockNumber
			hashs = msgNewBlock.BlockHash
			proposerSig = msgNewBlock.SigData
		} else {
			pos := indexOfSlice(voterAll, address) // voter address
			log.Debugf("Bitmap check, pos: %d, address: %s, all: %s", pos, address, epochVoter.VoteAddrList)
			if pos >= 0 {
				bmp.Set(uint32(pos))
				voteSig = append(voteSig, msgNewBlock.SigData)
			}
		}
	}

	if proposer == "" {
		return nil, fmt.Errorf("missing proposer sig msg, request id: %s", requestId)
	}

	if epoch != epochVoter.Epoch {
		return nil, fmt.Errorf("incorrect epoch, request id: %s, msg epoch: %d, current epoch: %d", requestId, epoch, epochVoter.Epoch)
	}
	if sequence != epochVoter.Sequence {
		return nil, fmt.Errorf("incorrect sequence, request id: %s, msg sequence: %d, current sequence: %d", requestId, sequence, epochVoter.Sequence)
	}

	voteSig = append([][]byte{proposerSig}, voteSig...)

	// check threshold
	threshold := Threshold(len(voterAll))
	if len(voteSig) < threshold {
		return nil, fmt.Errorf("threshold not reach, request id: %s, has sig: %d, threshold: %d", requestId, len(voteSig), threshold)
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

	msgBlock := bitcointypes.MsgNewBlockHashes{
		Proposer:         proposer,
		Vote:             votes,
		StartBlockNumber: startBlockNumber,
		BlockHash:        hashs,
	}

	return &msgBlock, nil
}
