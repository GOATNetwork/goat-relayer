package safebox

import (
	"context"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/types"
)

func (s *SafeboxProcessor) handleTssSign(ctx context.Context, msg types.TssSession) {
	s.logger.Infof("SafeboxProcessor handleTssSign, session id: %s", msg.SessionId)
	task, err := s.state.GetSafeboxTaskByTaskId(msg.TaskId)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor handleTssSign, session id: %s, task id: %s, error: %v", msg.SessionId, task.ID, err)
		return
	}

	if msg.SignExpiredTs < time.Now().Unix() {
		s.logger.Errorf("SafeboxProcessor handleTssSign, session id: %s, task id: %s, error: sign expired", msg.SessionId, task.ID)
		return
	}

	if task.Status != msg.Status {
		s.logger.Infof("SafeboxProcessor handleTssSign, session id: %s, local: %s, remote: %s, error: status not match", msg.SessionId, task.Status, msg.Status)
		return
	}

	if task.Amount != msg.Amount {
		s.logger.Errorf("SafeboxProcessor handleTssSign, session id: %s, local: %s, remote: %s, error: amount not match", msg.SessionId, task.Amount, msg.Amount)
		return
	}

	if task.DepositAddress != msg.DepositAddress {
		s.logger.Errorf("SafeboxProcessor handleTssSign, session id: %s, local: %s, remote: %s, error: deposit address not match", msg.SessionId, task.DepositAddress, msg.DepositAddress)
		return
	}

	s.tssMu.Lock()
	defer s.tssMu.Unlock()
	s.logger.Infof("SafeboxProcessor handleTssSign, session id: %s, task status: %s", msg.SessionId, task.Status)
	s.tssSession = &msg

	switch task.Status {
	case db.TASK_STATUS_RECEIVED:
		s.logger.Infof("SafeboxProcessor handleTssSign, session id: %s, task status: %s", msg.SessionId, task.Status)
		if task.FundingTxid != msg.FundingTxid || task.FundingOutIndex != msg.FundingOutIndex {
			s.logger.Errorf("SafeboxProcessor handleTssSign, session id: %s, task status: %s, error: funding txid or funding out index not match", msg.SessionId, task.Status)
			return
		}
		_, err = s.tssSigner.StartSign(ctx, msg.MessageToSign, msg.SessionId)
		if err != nil {
			s.logger.Errorf("SafeboxProcessor handleTssSign, session id: %s, task status: %s, error: %v", msg.SessionId, task.Status, err)
			return
		}
		return
	case db.TASK_STATUS_INIT:
		s.logger.Infof("SafeboxProcessor handleTssSign, session id: %s, task status: %s", msg.SessionId, task.Status)
		if task.TimelockTxid != msg.TimelockTxid || task.TimelockOutIndex != msg.TimelockOutIndex {
			s.logger.Errorf("SafeboxProcessor handleTssSign, session id: %s, task status: %s, error: timelock txid or timelock out index not match", msg.SessionId, task.Status)
			return
		}
		return
	case db.TASK_STATUS_CONFIRMED:
		// TODO: check timelock tx is confirmed
		return

	default:
		s.logger.Errorf("SafeboxProcessor handleTssSign, session id: %s, task status: %s", msg.SessionId, task.Status)
	}

}
