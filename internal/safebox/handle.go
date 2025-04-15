package safebox

import (
	"bytes"
	"context"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/types"
)

func (s *SafeboxProcessor) handleTssSign(ctx context.Context, msg types.TssSession) {
	s.logger.Infof("SafeboxProcessor handleTssSign - Start Tss Sign, SessionId: %s, TaskId: %d", msg.SessionId, msg.TaskId)

	task, err := s.state.GetSafeboxTaskByTaskId(msg.TaskId)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor handleTssSign - Failed to get task, SessionId: %s, TaskId: %d, Error: %v",
			msg.SessionId, msg.TaskId, err)
		return
	}
	s.logger.Infof("SafeboxProcessor handleTssSign - Retrieved task details, TaskId: %d, Status: %s, Amount: %d, DepositAddress: %s",
		task.TaskId, task.Status, task.Amount, task.DepositAddress)

	if msg.SignExpiredTs < time.Now().Unix() {
		s.logger.Errorf("SafeboxProcessor handleTssSign - Session expired, SessionId: %s, TaskId: %d, ExpiredAt: %d, CurrentTime: %d",
			msg.SessionId, task.TaskId, msg.SignExpiredTs, time.Now().Unix())
		return
	}

	if task.Status != msg.Status {
		s.logger.Infof("SafeboxProcessor handleTssSign - Status mismatch, SessionId: %s, LocalStatus: %s, RemoteStatus: %s",
			msg.SessionId, task.Status, msg.Status)
		return
	}

	if task.Amount != msg.Amount {
		s.logger.Errorf("SafeboxProcessor handleTssSign - Amount mismatch, SessionId: %s, LocalAmount: %d, RemoteAmount: %d",
			msg.SessionId, task.Amount, msg.Amount)
		return
	}

	if task.DepositAddress != msg.DepositAddress {
		s.logger.Errorf("SafeboxProcessor handleTssSign - Deposit address mismatch, SessionId: %s, LocalAddr: %s, RemoteAddr: %s",
			msg.SessionId, task.DepositAddress, msg.DepositAddress)
		return
	}

	s.tssMu.Lock()
	defer s.tssMu.Unlock()
	s.logger.Infof("SafeboxProcessor handleTssSign - Processing Tss Sign, SessionId: %s, TaskStatus: %s", msg.SessionId, task.Status)
	s.tssSession = &msg

	switch task.Status {
	case db.TASK_STATUS_RECEIVED:
		s.logger.Infof("SafeboxProcessor handleTssSign - Processing TASK_STATUS_RECEIVED - SessionId: %s", msg.SessionId)
		if task.FundingTxid != msg.FundingTxid || task.FundingOutIndex != msg.FundingOutIndex {
			s.logger.Errorf("SafeboxProcessor handleTssSign - Funding details mismatch, SessionId: %s, LocalTxid: %s, RemoteTxid: %s, LocalOutIndex: %d, RemoteOutIndex: %d",
				msg.SessionId, task.FundingTxid, msg.FundingTxid, task.FundingOutIndex, msg.FundingOutIndex)
			return
		}
		_, err = s.tssSigner.StartSign(ctx, msg.MessageToSign, msg.SessionId)
		if err != nil {
			s.logger.Errorf("SafeboxProcessor handleTssSign - Start sign failed, SessionId: %s, TaskStatus: %s, Error: %v",
				msg.SessionId, task.Status, err)
			return
		}
		s.logger.Infof("SafeboxProcessor handleTssSign - Successfully sign task TASK_STATUS_RECEIVED, SessionId: %s", msg.SessionId)

	case db.TASK_STATUS_INIT:
		s.logger.Infof("SafeboxProcessor handleTssSign - Processing TASK_STATUS_INIT - SessionId: %s", msg.SessionId)
		task, err = s.state.GetSafeboxTaskByTaskId(msg.TaskId)
		if err != nil {
			s.logger.Errorf("SafeboxProcessor handleTssSign - Failed to get task, SessionId: %s, TaskId: %d, Error: %v",
				msg.SessionId, msg.TaskId, err)
			return
		}
		timelockAddress, witnessScript, err := types.GenerateTimeLockP2WSHAddress(msg.Pubkey, time.Unix(int64(msg.TimelockEndTime), 0), types.GetBTCNetwork(config.AppConfig.BTCNetworkType))
		if err != nil {
			s.logger.Errorf("SafeboxProcessor handleTssSign - Failed to generate timelock address, SessionId: %s, Error: %v",
				msg.SessionId, err)
			return
		}
		if task.TimelockAddress != timelockAddress.EncodeAddress() || !bytes.Equal(task.WitnessScript, witnessScript) {
			s.logger.Errorf("SafeboxProcessor handleTssSign - Timelock details mismatch, SessionId: %s, LocalTxid: %s, RemoteTxid: %s, LocalOutIndex: %d, RemoteOutIndex: %d",
				msg.SessionId, task.TimelockAddress, timelockAddress, task.TimelockOutIndex, msg.TimelockOutIndex)
			return
		}
		if task.TimelockTxid != msg.TimelockTxid || task.TimelockOutIndex != msg.TimelockOutIndex {
			s.logger.Errorf("SafeboxProcessor handleTssSign - Timelock details mismatch, SessionId: %s, LocalTxid: %s, RemoteTxid: %s, LocalOutIndex: %d, RemoteOutIndex: %d",
				msg.SessionId, task.TimelockTxid, msg.TimelockTxid, task.TimelockOutIndex, msg.TimelockOutIndex)
			return
		}
		_, err = s.tssSigner.StartSign(ctx, msg.MessageToSign, msg.SessionId)
		if err != nil {
			s.logger.Errorf("SafeboxProcessor handleTssSign - Start sign failed, SessionId: %s, TaskStatus: %s, Error: %v",
				msg.SessionId, task.Status, err)
			return
		}
		s.logger.Infof("SafeboxProcessor handleTssSign - Successfully sign task TASK_STATUS_INIT, SessionId: %s", msg.SessionId)
	case db.TASK_STATUS_CONFIRMED:
		s.logger.Infof("SafeboxProcessor handleTssSign - Processing TASK_STATUS_CONFIRMED - SessionId: %s", msg.SessionId)
		// TODO: check timelock tx is confirmed

	default:
		s.logger.Errorf("SafeboxProcessor handleTssSign - Unknown task status SessionId: %s, Status: %s",
			msg.SessionId, task.Status)
	}

	s.logger.Infof("SafeboxProcessor handleTssSign - Completed SessionId: %s", msg.SessionId)
}
