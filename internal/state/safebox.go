package state

import (
	"github.com/goatnetwork/goat-relayer/internal/db"
)

type SafeboxTaskStateStore interface {
	GetSafeboxTasks() ([]*db.SafeboxTask, error)
	GetSafeboxTaskByTaskId(taskId uint64) (*db.SafeboxTask, error)
	GetSafeboxTaskByStatus(limit int, statuses ...string) ([]*db.SafeboxTask, error)
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
