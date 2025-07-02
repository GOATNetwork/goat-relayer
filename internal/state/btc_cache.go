package state

import (
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	"gorm.io/gorm"
)

func (s *State) GetBtcSyncStatus() (*db.BtcSyncStatus, error) {
	s.btcHeadMu.RLock()
	defer s.btcHeadMu.RUnlock()

	var syncStatus db.BtcSyncStatus
	result := s.dbm.GetBtcCacheDB().First(&syncStatus)
	if result.Error != nil {
		return nil, result.Error
	}
	return &syncStatus, nil
}

func (s *State) SaveBtcSyncStatus(syncStatus *db.BtcSyncStatus) error {
	s.btcHeadMu.Lock()
	defer s.btcHeadMu.Unlock()

	result := s.dbm.GetBtcCacheDB().Save(syncStatus)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (s *State) CreateBtcSyncStatus(confirmedHeight, unconfirmHeight int64) (*db.BtcSyncStatus, error) {
	s.btcHeadMu.Lock()
	defer s.btcHeadMu.Unlock()

	var syncStatus db.BtcSyncStatus
	result := s.dbm.GetBtcCacheDB().First(&syncStatus)
	if result.Error != nil && result.Error == gorm.ErrRecordNotFound {
		syncStatus = db.BtcSyncStatus{
			ConfirmedHeight: confirmedHeight,
			UnconfirmHeight: unconfirmHeight,
			UpdatedAt:       time.Now(),
		}
		result = s.dbm.GetBtcCacheDB().Create(&syncStatus)
		if result.Error != nil {
			return nil, result.Error
		}
		return &syncStatus, nil
	}
	return nil, result.Error
}
