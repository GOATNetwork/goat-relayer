package bls

import (
	"context"
	"fmt"
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
	default:
		// check e['msg_type'] from libp2p
		log.Debugf("Unknown event handleSigReceive type, %v", e)
	}
}

func (s *Signer) RetrySubmit(ctx context.Context, requestId string, msg interface{}, retries int) error {
	var err error
	for i := 0; i <= retries; i++ {
		resultTx, err := s.layer2Listener.SubmitToConsensus(ctx, msg)
		if err == nil {
			if resultTx.TxResult.Code != 0 {
				return fmt.Errorf("tx execute error, %v", resultTx.TxResult.Log)
			}
			return nil
		} else if i == retries {
			return err
		}
		log.Warnf("Retrying to submit msg to RPC, attempt %d, request id: %s", i+1, requestId)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second * 2):
		}
	}
	return err
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

func indexOfSlice(sl []string, s string) int {
	for i, addr := range sl {
		if addr == s {
			return i
		}
	}
	return -1
}

func Threshold(total int) int {
	// >= 2/3
	return (total*2 + 2) / 3
}
