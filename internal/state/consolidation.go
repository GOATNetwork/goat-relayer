package state

import (
	"github.com/goatnetwork/goat-relayer/internal/db"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type ConsolidationStateStore interface {
	HasConsolidationInProgress() bool
}

func (s *State) HasConsolidationInProgress() bool {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	var order db.SendOrder
	err := s.dbm.GetWalletDB().Where("status IN (?)", []string{db.ORDER_STATUS_AGGREGATING, db.ORDER_STATUS_INIT, db.ORDER_STATUS_PENDING}).Order("id desc").First(&order).Error
	if err == gorm.ErrRecordNotFound {
		return false
	}
	if err != nil {
		log.Errorf("State HasConsolidationInProgress get sendorder db error: %v", err)
	}
	return true
}
