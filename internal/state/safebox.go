package state

import (
	"fmt"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	"gorm.io/gorm"
)

type SafeboxTaskStateStore interface {
	GetSafeboxTasks() ([]*db.SafeboxTask, error)
	GetSafeboxTaskByTaskId(taskId uint64) (*db.SafeboxTask, error)
	GetSafeboxTaskByStatus(limit int, statuses ...string) ([]*db.SafeboxTask, error)
	RevertSafeboxTaskToReceivedOKByTimelockTxid(timelockTxid string) error
}

// RevertSafeboxTaskToReceivedOKByTimelockTxid revert safebox task to received ok by timelock txid
func (s *State) RevertSafeboxTaskToReceivedOKByTimelockTxid(timelockTxid string) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		taskDeposit, err := s.queryProcessingSafeboxTaskByTimelockTxid(tx, timelockTxid)
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		if err == gorm.ErrRecordNotFound {
			return fmt.Errorf("task deposit not found")
		}
		taskDeposit.Status = db.TASK_STATUS_RECEIVED_OK
		taskDeposit.UpdatedAt = time.Now()
		return tx.Save(&taskDeposit).Error
	})
	return err
}

func (s *State) GetSafeboxTaskByTaskId(taskId uint64) (*db.SafeboxTask, error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	var task db.SafeboxTask
	err := s.dbm.GetWalletDB().Where("task_id = ?", taskId).First(&task).Error
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *State) GetSafeboxTaskByStatus(limit int, statuses ...string) ([]*db.SafeboxTask, error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	var tasks []*db.SafeboxTask
	err := s.dbm.GetWalletDB().Model(&db.SafeboxTask{}).Where("status IN (?)", statuses).Order("id desc").Limit(limit).Find(&tasks).Error
	if err != nil {
		return nil, err
	}
	return tasks, nil
}

func (s *State) GetSafeboxTasks() ([]*db.SafeboxTask, error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	var tasks []*db.SafeboxTask
	err := s.dbm.GetWalletDB().Where("status IN (?)", []string{db.TASK_STATUS_RECEIVED_OK}).Order("id desc").Find(&tasks).Error
	if err != nil {
		return nil, err
	}
	return tasks, nil
}
