package safebox

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/types"
)

func (s *SafeboxProcessor) handleTssSign(ctx context.Context, msg types.MsgSignSafeboxTask) {
	s.logger.Infof("SafeboxProcessor handleTssSign - Start Tss Sign, SessionId: %s, TaskId: %d", msg.RequestId, msg)

	var task *db.SafeboxTask
	err := json.Unmarshal(msg.SafeboxTask, &task)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor handleTssSign - Failed to unmarshal safebox task, SessionId: %s, Error: %v",
			msg.RequestId, err)
		return
	}
	taskInDb, err := s.state.GetSafeboxTaskByTaskId(task.TaskId)
	if err != nil {
		s.logger.Errorf("SafeboxProcessor handleTssSign - Failed to get task, SessionId: %s, TaskId: %d, Error: %v",
			msg.RequestId, task.TaskId, err)
		return
	}
	s.logger.Infof("SafeboxProcessor handleTssSign - Retrieved task details, TaskId: %d, Status: %s, Amount: %d, DepositAddress: %s",
		task.TaskId, task.Status, task.Amount, task.DepositAddress)

	if msg.CheckExpired() {
		s.logger.Errorf("SafeboxProcessor handleTssSign - Session expired, SessionId: %s, TaskId: %d, ExpiredAt: %d, CurrentTime: %d",
			msg.RequestId, task.TaskId, msg.CreateTime, time.Now().Unix())
		return
	}

	if task.Status != taskInDb.Status {
		s.logger.Infof("SafeboxProcessor handleTssSign - Status mismatch, SessionId: %s, LocalStatus: %s, RemoteStatus: %s",
			msg.RequestId, task.Status, taskInDb.Status)
		return
	}

	if task.Amount != taskInDb.Amount {
		s.logger.Errorf("SafeboxProcessor handleTssSign - Amount mismatch, SessionId: %s, LocalAmount: %d, RemoteAmount: %d",
			msg.RequestId, task.Amount, taskInDb.Amount)
		return
	}

	if task.DepositAddress != taskInDb.DepositAddress {
		s.logger.Errorf("SafeboxProcessor handleTssSign - Deposit address mismatch, SessionId: %s, LocalAddr: %s, RemoteAddr: %s",
			msg.RequestId, task.DepositAddress, taskInDb.DepositAddress)
		return
	}

	s.tssMu.Lock()
	defer s.tssMu.Unlock()
	s.logger.Infof("SafeboxProcessor handleTssSign - Processing Tss Sign, SessionId: %s, TaskStatus: %s", msg.RequestId, task.Status)
	s.tssSession = &msg

	switch task.Status {
	case db.TASK_STATUS_RECEIVED:
		s.logger.Infof("SafeboxProcessor handleTssSign - Processing TASK_STATUS_RECEIVED - SessionId: %s", msg.RequestId)
		if task.FundingTxid != taskInDb.FundingTxid || task.FundingOutIndex != taskInDb.FundingOutIndex {
			s.logger.Errorf("SafeboxProcessor handleTssSign - Funding details mismatch, SessionId: %s, LocalTxid: %s, RemoteTxid: %s, LocalOutIndex: %d, RemoteOutIndex: %d",
				msg.RequestId, task.FundingTxid, taskInDb.FundingTxid, task.FundingOutIndex, taskInDb.FundingOutIndex)
			return
		}
		_, err = s.tssSigner.StartSign(ctx, msg.SigData, msg.RequestId)
		if err != nil {
			s.logger.Errorf("SafeboxProcessor handleTssSign - Start sign failed, SessionId: %s, TaskStatus: %s, Error: %v",
				msg.RequestId, task.Status, err)
			return
		}
		s.logger.Infof("SafeboxProcessor handleTssSign - Successfully sign task TASK_STATUS_RECEIVED, SessionId: %s", msg.RequestId)

	case db.TASK_STATUS_INIT:
		s.logger.Infof("SafeboxProcessor handleTssSign - Processing TASK_STATUS_INIT - SessionId: %s", msg.RequestId)
		timelockAddress, witnessScript, err := types.GenerateTimeLockP2WSHAddress(task.Pubkey, time.Unix(int64(task.TimelockEndTime), 0), types.GetBTCNetwork(config.AppConfig.BTCNetworkType))
		if err != nil {
			s.logger.Errorf("SafeboxProcessor handleTssSign - Failed to generate timelock address, SessionId: %s, Error: %v",
				msg.RequestId, err)
			return
		}
		if task.TimelockAddress != timelockAddress.EncodeAddress() || !bytes.Equal(task.WitnessScript, witnessScript) {
			s.logger.Errorf("SafeboxProcessor handleTssSign - Timelock details mismatch, SessionId: %s, LocalTxid: %s, RemoteTxid: %s, LocalOutIndex: %d, RemoteOutIndex: %d",
				msg.RequestId, task.TimelockAddress, timelockAddress, task.TimelockOutIndex, taskInDb.TimelockOutIndex)
			return
		}
		if task.TimelockTxid != taskInDb.TimelockTxid || task.TimelockOutIndex != taskInDb.TimelockOutIndex {
			s.logger.Errorf("SafeboxProcessor handleTssSign - Timelock details mismatch, SessionId: %s, LocalTxid: %s, RemoteTxid: %s, LocalOutIndex: %d, RemoteOutIndex: %d",
				msg.RequestId, task.TimelockTxid, taskInDb.TimelockTxid, task.TimelockOutIndex, taskInDb.TimelockOutIndex)
			return
		}
		_, err = s.tssSigner.StartSign(ctx, msg.SigData, msg.RequestId)
		if err != nil {
			s.logger.Errorf("SafeboxProcessor handleTssSign - Start sign failed, RequestId: %s, TaskStatus: %s, Error: %v",
				msg.RequestId, task.Status, err)
			return
		}
		s.logger.Infof("SafeboxProcessor handleTssSign - Successfully sign task TASK_STATUS_INIT, RequestId: %s", msg.RequestId)
	case db.TASK_STATUS_CONFIRMED:
		s.logger.Infof("SafeboxProcessor handleTssSign - Processing TASK_STATUS_CONFIRMED - RequestId: %s", msg.RequestId)
		// TODO: check timelock tx is confirmed

	default:
		s.logger.Errorf("SafeboxProcessor handleTssSign - Unknown task status RequestId: %s, Status: %s",
			msg.RequestId, task.Status)
	}

	s.logger.Infof("SafeboxProcessor handleTssSign - Completed RequestId: %s", msg.RequestId)
}
