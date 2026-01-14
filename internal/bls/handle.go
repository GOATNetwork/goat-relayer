package bls

import (
	"context"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/goatnetwork/goat-relayer/internal/types"
	log "github.com/sirupsen/logrus"
)

func (s *Signer) checkTimeouts() {
	s.sigMu.Lock()
	now := time.Now()
	expiredRequests := make([]string, 0)

	for requestId, expireTime := range s.sigTimeoutMap {
		if now.After(expireTime) {
			log.Debugf("Request %s has timed out, removing from sigMap", requestId)
			expiredRequests = append(expiredRequests, requestId)
		}
	}
	s.sigMu.Unlock()

	for _, requestId := range expiredRequests {
		s.removeSigMap(requestId, true)
	}
}

func (s *Signer) handleSigStart(ctx context.Context, event interface{}) {
	switch e := event.(type) {
	case types.MsgSignNewBlock:
		log.Debugf("Event handleSigStart is of type MsgSignNewBlock, request id %s", e.RequestId)
		if err := s.handleSigStartNewBlock(ctx, e); err != nil {
			log.Errorf("Error handleSigStart MsgSignNewBlock, %v", err)
			// feedback SigFailed
			s.state.EventBus.Publish(state.SigFailed, e)
		}
	case types.MsgSignDeposit:
		log.Debugf("Event handleDepositReceive is of type MsgSignDeposit, request id %s", e.RequestId)
		if err := s.handleSigStartNewDeposit(ctx, e); err != nil {
			log.Errorf("Error handleSigStart MsgSignDeposit, %v", err)
			// feedback SigFailed
			s.state.EventBus.Publish(state.SigFailed, e)
		}
	case types.MsgSignSendOrder:
		log.Debugf("Event handleSigStartSendOrder is of type MsgSignSendOrder, request id %s", e.RequestId)
		if err := s.handleSigStartSendOrder(ctx, e); err != nil {
			log.Errorf("Error handleSigStart MsgSignSendOrder, %v", err)
			// feedback SigFailed
			s.state.EventBus.Publish(state.SigFailed, e)
		}
	case types.MsgSignFinalizeWithdraw:
		log.Debugf("Event handleSigStartFinalizeWithdraw is of type MsgSignFinalizeWithdraw, request id %s", e.RequestId)
		if err := s.handleSigStartWithdrawFinalize(ctx, e); err != nil {
			log.Errorf("Error handleSigStart MsgSignFinalizeWithdraw, %v", err)
			// feedback SigFailed
			s.state.EventBus.Publish(state.SigFailed, e)
		}
	case types.MsgSignCancelWithdraw:
		log.Debugf("Event handleSigStartCancelWithdraw is of type MsgSignCancelWithdraw, request id %s", e.RequestId)
		if err := s.handleSigStartWithdrawCancel(ctx, e); err != nil {
			log.Errorf("Error handleSigStart MsgSignCancelWithdraw, %v", err)
			// feedback SigFailed
			s.state.EventBus.Publish(state.SigFailed, e)
		}
	case types.MsgSignNewVoter:
		log.Debugf("Event handleSigStartNewVoter is of type MsgSignNewVoter, request id %s", e.RequestId)
		if err := s.handleSigStartNewVoter(ctx, e); err != nil {
			log.Errorf("Error handleSigStart MsgSignNewVoter, %v", err)
			// feedback SigFailed
			s.state.EventBus.Publish(state.SigFailed, e)
		}
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
		if err := s.handleSigReceiveNewBlock(ctx, e); err != nil {
			log.Errorf("Error handleSigReceive MsgSignNewBlock, %v", err)
			// feedback SigFailed
			s.state.EventBus.Publish(state.SigFailed, e)
		}
	case types.MsgSignSendOrder:
		log.Debugf("Event handleSigReceive is of type MsgSignSendOrder, request id %s", e.RequestId)
		if err := s.handleSigReceiveSendOrder(ctx, e); err != nil {
			log.Errorf("Error handleSigReceive MsgSignSendOrder, %v", err)
			// feedback SigFailed
			s.state.EventBus.Publish(state.SigFailed, e)
		}
	case types.MsgSignNewVoter:
		// only proposer will process new voter sig and broadcast to consensus
		log.Debugf("Event handleSigReceive is of type MsgSignNewVoter, request id %s", e.RequestId)
		if err := s.handleSigReceiveNewVoter(ctx, e); err != nil {
			log.Errorf("Error handleSigReceive MsgSignNewVoter, %v", err)
			// feedback SigFailed
			s.state.EventBus.Publish(state.SigFailed, e)
		}
	default:
		// check e['msg_type'] from libp2p
		log.Debugf("Unknown event handleSigReceive type, %v", e)
	}
}

func (s *Signer) sigExists(requestId string) (map[string]interface{}, bool) {
	s.sigMu.RLock()
	defer s.sigMu.RUnlock()
	data, ok := s.sigMap[requestId]
	return data, ok
}

func (s *Signer) removeSigMap(requestId string, reportTimeout bool) {
	s.sigMu.Lock()
	defer s.sigMu.Unlock()
	if reportTimeout {
		if voteMap, ok := s.sigMap[requestId]; ok {
			if voteMsg, ok := voteMap[s.address]; ok {
				log.Debugf("Report timeout when remove sig map, found msg, request id %s, proposer %s", requestId, s.address)
				s.state.EventBus.Publish(state.SigTimeout, voteMsg)
			}
		}
	}
	delete(s.sigMap, requestId)
	delete(s.sigTimeoutMap, requestId)
}
