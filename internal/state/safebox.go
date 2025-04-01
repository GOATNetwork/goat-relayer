package state

import (
	"github.com/goatnetwork/goat-relayer/internal/db"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type SafeboxTaskStateStore interface {
	HasSafeboxTaskInProgress() bool
	GetSafeboxTasks() ([]*db.SafeboxTask, error)
}

func (s *State) HasSafeboxTaskInProgress() bool {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	var task db.SafeboxTask
	err := s.dbm.GetWalletDB().Where("status IN (?)", []string{db.TASK_STATUS_RECEIVED, db.TASK_STATUS_AGGREGATING}).Order("id desc").First(&task).Error
	if err == gorm.ErrRecordNotFound {
		return false
	}
	if err != nil {
		log.Errorf("State HasSafeboxTaskInProgress get safebox task db error: %v", err)
	}
	return true
}

func (s *State) GetSafeboxTasks() ([]*db.SafeboxTask, error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	var tasks []*db.SafeboxTask
	err := s.dbm.GetWalletDB().Where("status IN (?)", []string{db.TASK_STATUS_RECEIVED, db.TASK_STATUS_AGGREGATING}).Order("id desc").Find(&tasks).Error
	if err != nil {
		return nil, err
	}
	return tasks, nil
}
