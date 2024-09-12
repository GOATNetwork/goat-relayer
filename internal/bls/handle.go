package bls

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/p2p"
	"github.com/goatnetwork/goat-relayer/internal/types"
	goatcryp "github.com/goatnetwork/goat/pkg/crypto"
	bitcointypes "github.com/goatnetwork/goat/x/bitcoin/types"
	relayertypes "github.com/goatnetwork/goat/x/relayer/types"
	"github.com/kelindar/bitmap"
	log "github.com/sirupsen/logrus"
)

func (s *Signer) handleSigStart(ctx context.Context, event interface{}) {
	switch e := event.(type) {
	case types.MsgSignNewBlock:
		log.Debugf("Event handleSigStart is of type MsgSignNewBlock, request id %s", e.RequestId)

		canSign := s.CanSign()
		isProposer := s.IsProposer()
		if !canSign || !isProposer {
			log.Debugf("Ignore SigStart request id %s, canSign: %v, isProposer: %v", e.RequestId, canSign, isProposer)
			log.Debugf("Current l2 context, catching up: %v, self address: %s, proposer: %s", s.state.GetL2Info().Syncing, s.address, s.state.GetEpochVoter().Proposer)
			return
		}

		if s.state.GetL2Info().LatestBtcHeight+1 != e.StartBlockNumber {
			log.Errorf("Error SigStart startBlockNumber %d, request id %s", e.StartBlockNumber, e.RequestId)
			return
		}

		// epochVoter := s.state.GetEpochVoter()

		// request id format: BTCHEAD:StartBlockNumber
		// check map
		_, ok := s.sigMap[e.RequestId]
		if ok {
			log.Errorf("SigStart exists, request id: %s", e.RequestId)
			return
		}

		btcHeadSigQueue := s.state.GetBtcHeadSigQueue()
		var blockHashes [][]byte
		for _, btcBlock := range btcHeadSigQueue {
			log.Infof("Signing BTC block from SigQueue, height: %d, hash: %s", btcBlock.Height, btcBlock.Hash)
			blockHashes = append(blockHashes, []byte(btcBlock.Hash))
		}
		e.BlockHash = blockHashes

		// build sign
		newSign := &types.MsgSignNewBlock{
			MsgSign: types.MsgSign{
				RequestId:    e.RequestId,
				Sequence:     e.Sequence,
				Epoch:        e.Epoch,
				IsProposer:   true,
				VoterAddress: s.address,
				SigData:      s.makeSigNewBlock(e.StartBlockNumber, e.BlockHash),
				CreateTime:   time.Now().Unix(),
			},
			StartBlockNumber: e.StartBlockNumber,
			BlockHash:        e.BlockHash,
		}

		// p2p broadcast
		p2pMsg := p2p.Message{
			MessageType: p2p.MessageTypeSigReq,
			RequestId:   e.RequestId,
			Data:        *newSign,
		}

		// lock
		s.mu.Lock()
		defer s.mu.Unlock()

		ctx1, cancel := context.WithCancel(ctx)
		defer cancel()
		p2p.PublishMessage(ctx1, p2pMsg)
		s.sigMap[e.RequestId] = make(map[string]interface{})
		s.sigMap[e.RequestId][s.address] = *newSign
		log.Infof("SigStart broadcast ok, request id: %s", e.RequestId)

		// If voters count is 1, should submit soon
		// UNCHECK aggregate
		rpcMsg, err := s.aggSigNewBlock(e.RequestId)
		if err != nil {
			log.Warnf("SigStart proposer process aggregate sig, request id: %s, err: %v", e.RequestId, err)
			return
		}

		err = s.layer2Listener.SubmitToConsensus(ctx1, rpcMsg)
		if err != nil {
			// TODO add retry logic
			log.Errorf("SigStart proposer submit NewBlock to RPC error, request id: %s, err: %v", e.RequestId, err)
			return
		}
		s.removeSigMap(e.RequestId)
		log.Infof("SigStart proposer submit NewBlock to RPC ok, request id: %s", e.RequestId)

	case types.MsgSignDeposit:
		log.Debugf("Event handleSigStart is of type MsgSignDeposit, request id %s", e.RequestId)
	default:
		log.Debug("Unknown event handleSigStart type")
	}
}

// handleSigReceive will only response for MsgSign
// when self is proposer, collect the voter sig and aggreate
// when self is voter, sign MsgSign.IsProposer=1 then broadcast, others ignore
func (s *Signer) handleSigReceive(ctx context.Context, event interface{}) {
	switch e := event.(type) {
	case types.MsgSignNewBlock:
		log.Debugf("Event handleSigReceive is of type MsgSignNewBlock, request id %s", e.RequestId)
		canSign := s.CanSign()
		isProposer := s.IsProposer()
		if !canSign {
			log.Debugf("Ignore SigStart request id %s, canSign: %v, isProposer: %v", e.RequestId, canSign, isProposer)
			return
		}
		epochVoter := s.state.GetEpochVoter()
		l2Info := s.state.GetL2Info()
		if isProposer {
			// collect voter sig
			if e.IsProposer {
				return
			}
			voteMap, ok := s.sigMap[e.RequestId]
			if !ok {
				log.Errorf("SigReceive proposer process no sig found, request id: %s", e.RequestId)
				return
			}
			_, ok = voteMap[e.VoterAddress]
			if ok {
				log.Warnf("SigReceive proposer process voter multi receive, request id: %s, voter address: %s", e.RequestId, e.VoterAddress)
				return
			}
			voteMap[e.VoterAddress] = e

			// UNCHECK aggregate
			rpcMsg, err := s.aggSigNewBlock(e.RequestId)
			if err != nil {
				log.Warnf("SigReceive proposer process aggregate sig, request id: %s, err: %v", e.RequestId, err)
				return
			}

			// lock
			s.mu.Lock()
			defer s.mu.Unlock()

			ctx1, cancel := context.WithCancel(ctx)
			defer cancel()
			err = s.layer2Listener.SubmitToConsensus(ctx1, rpcMsg)
			if err != nil {
				// TODO add retry logic
				log.Errorf("SigReceive proposer submit NewBlock to RPC error, request id: %s, err: %v", e.RequestId, err)
				return
			}
			s.removeSigMap(e.RequestId)
			log.Infof("SigReceive proposer submit NewBlock to RPC ok, request id: %s", e.RequestId)

		} else {
			if !e.IsProposer {
				return
			}

			// validate startBlockNumber, hashs local
			if l2Info.LatestBtcHeight+1 != e.StartBlockNumber {
				log.Warnf("MsgSignDeposit handleSigReceive StartBlockNumber does not match LatestBtcHeight, request id %s, StartBlockNumber: %d, LatestBtcHeight plus 1: %d", e.RequestId, e.StartBlockNumber, l2Info.LatestBtcHeight+1)
				return
			}
			// TODO hash comparation

			// validate epoch
			if e.Epoch != epochVoter.Epoch {
				log.Warnf("MsgSignDeposit handleSigReceive epoch does not match, request id %s, msg epoch: %d, current epoch: %d", e.RequestId, e.Epoch, epochVoter.Epoch)
				return
			}
			newSign := &types.MsgSignNewBlock{
				MsgSign: types.MsgSign{
					RequestId:    e.RequestId,
					Sequence:     e.Sequence,
					Epoch:        e.Epoch,
					IsProposer:   false,
					VoterAddress: s.address,
					SigData:      s.makeSigNewBlock(e.StartBlockNumber, e.BlockHash),
					CreateTime:   time.Now().Unix(),
				},
				StartBlockNumber: e.StartBlockNumber,
				BlockHash:        e.BlockHash,
			}
			// p2p broadcast
			p2pMsg := p2p.Message{
				MessageType: p2p.MessageTypeSigResp,
				RequestId:   newSign.RequestId,
				Data:        *newSign,
			}
			// lock
			s.mu.Lock()
			defer s.mu.Unlock()

			ctx1, cancel := context.WithCancel(ctx)
			defer cancel()
			p2p.PublishMessage(ctx1, p2pMsg)
			log.Infof("SigReceive broadcast ok, request id: %s", e.RequestId)
		}
	case types.MsgSignDeposit:
		log.Debugf("Event handleSigReceive is of type MsgSignDeposit, request id %s", e.RequestId)
	default:
		log.Debug("Unknown event handleSigReceive type")
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
	sigDoc := relayertypes.VoteSignDoc(msgBlock.MethodName(), config.AppConfig.GoatChainID, epochVoter.Proposer, epochVoter.Seqeuence, uint64(epochVoter.Epoch), msgBlock.VoteSigDoc())
	return goatcryp.Sign(s.sk, sigDoc)
}

func (s *Signer) aggSigNewBlock(requestId string) (*bitcointypes.MsgNewBlockHashes, error) {
	epochVoter := s.state.GetEpochVoter()

	voteMap, ok := s.sigMap[requestId]
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
			proposer = address
			sequence = msgNewBlock.Sequence
			epoch = msgNewBlock.Epoch
			startBlockNumber = msgNewBlock.StartBlockNumber
			hashs = msgNewBlock.BlockHash
			proposerSig = msgNewBlock.SigData
		} else {
			pos := indexOfSlice(voterAll, address)
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

func (s *Signer) removeSigMap(requestId string) {
	delete(s.sigMap, requestId)
}

func indexOfSlice(sl []string, s string) int {
	for i, addr := range sl {
		if addr == s {
			return i
		}
	}
	return -1
}

func Threshold(total int) int {
	return int(math.Ceil(float64(total) * 2 / 3))
}
