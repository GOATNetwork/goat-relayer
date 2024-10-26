package state

import (
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/types"
	"gorm.io/gorm"
)

func (s *State) UpdateBtcNetworkFee(fastestFee uint64, halfHourFee uint64, hourFee uint64) {
	s.btcHeadMu.Lock()
	defer s.btcHeadMu.Unlock()

	s.btcHeadState.NetworkFee = types.BtcNetworkFee{
		FastestFee:  fastestFee,
		HalfHourFee: halfHourFee,
		HourFee:     hourFee,
	}
}

func (s *State) UpdateBtcSyncing(syncing bool) {
	s.btcHeadMu.Lock()
	defer s.btcHeadMu.Unlock()

	s.btcHeadState.Syncing = syncing
}

/*
AddUnconfirmBtcBlock
when btc scanner detected a new block, save to unconfirmed,
proposer will start an off-chain signature
*/
func (s *State) AddUnconfirmBtcBlock(height uint64, hash string) error {
	s.btcHeadMu.Lock()
	defer s.btcHeadMu.Unlock()

	// check if exist, if not save to db
	_, err := s.queryBtcBlockByHeight(height)
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}
	if err == nil {
		// exist height
		return nil
	}

	status := db.BTC_BLOCK_STATUS_UNCONFIRM
	if height <= s.btcHeadState.Latest.Height {
		status = db.BTC_BLOCK_STATUS_PROCESSED
	}

	btcBlock := &db.BtcBlock{
		Status:    status,
		UpdatedAt: time.Now(),
		Height:    height,
		Hash:      hash,
	}
	result := s.dbm.GetBtcLightDB().Save(btcBlock)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

func (s *State) SaveConfirmBtcBlock(height uint64, hash string) error {
	s.btcHeadMu.Lock()
	defer s.btcHeadMu.Unlock()

	btcBlock, err := s.queryBtcBlockByHeight(height)
	status := db.BTC_BLOCK_STATUS_CONFIRMED
	if height <= s.btcHeadState.Latest.Height {
		status = db.BTC_BLOCK_STATUS_PROCESSED
	}

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			btcBlock = &db.BtcBlock{
				Status:    status,
				UpdatedAt: time.Now(),
				Height:    height,
				Hash:      hash,
			}
		} else {
			// DB error
			return err
		}
	} else {
		if btcBlock.Status != db.BTC_BLOCK_STATUS_PROCESSED {
			btcBlock.Status = status
			btcBlock.Hash = hash
		}
		btcBlock.UpdatedAt = time.Now()
	}
	result := s.dbm.GetBtcLightDB().Save(btcBlock)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (s *State) UpdateProcessedBtcBlock(block uint64, height uint64, hash string) error {
	s.btcHeadMu.Lock()
	defer s.btcHeadMu.Unlock()

	btcBlock, err := s.queryBtcBlockByHeight(height)
	if err != nil {
		// query db failed, update cache
		// this will happen when L2 scan fast than btc
		if err != gorm.ErrRecordNotFound {
			s.btcHeadState.Latest = db.BtcBlock{
				Height:    height,
				Hash:      hash,
				UpdatedAt: time.Now(),
			}
			return err
		} else {
			btcBlock = &db.BtcBlock{
				Height:    height,
				Hash:      hash,
				Status:    db.BTC_BLOCK_STATUS_CONFIRMED,
				UpdatedAt: time.Now(),
			}
		}
	}

	if btcBlock.Status == db.BTC_BLOCK_STATUS_PROCESSED {
		return nil
	}
	btcBlock.Status = db.BTC_BLOCK_STATUS_PROCESSED

	// update height
	result := s.dbm.GetBtcLightDB().Save(btcBlock)
	if result.Error != nil {
		return result.Error
	}

	s.btcHeadState.Latest = *btcBlock
	for i, bb := range s.btcHeadState.UnconfirmQueue {
		if bb.Height == height {
			if i == len(s.btcHeadState.UnconfirmQueue)-1 {
				s.btcHeadState.UnconfirmQueue = s.btcHeadState.UnconfirmQueue[:i]
			} else {
				s.btcHeadState.UnconfirmQueue = append(s.btcHeadState.UnconfirmQueue[:i], s.btcHeadState.UnconfirmQueue[i+1:]...)
			}
			break
		}
	}
	for i, bb := range s.btcHeadState.SigQueue {
		if bb.Height == height {
			if i == len(s.btcHeadState.SigQueue)-1 {
				s.btcHeadState.SigQueue = s.btcHeadState.SigQueue[:i]
			} else {
				s.btcHeadState.SigQueue = append(s.btcHeadState.SigQueue[:i], s.btcHeadState.SigQueue[i+1:]...)
			}
			break
		}
	}

	return nil
}

// GetBtcBlockForSign
func (s *State) GetBtcBlockForSign(size int) ([]*db.BtcBlock, error) {
	s.btcHeadMu.RLock()
	defer s.btcHeadMu.RUnlock()

	from := s.GetL2Info().LatestBtcHeight
	var btcBlocks []*db.BtcBlock
	result := s.dbm.GetBtcLightDB().Where("height > ?", from).Order("height asc").Limit(size).Find(&btcBlocks)
	if result.Error != nil {
		return nil, result.Error
	}
	return btcBlocks, nil
}

// GetCurrentBtcBlock
func (s *State) GetCurrentBtcBlock() (db.BtcBlock, error) {
	s.btcHeadMu.RLock()
	defer s.btcHeadMu.RUnlock()

	return s.btcHeadState.Latest, nil
}

func (s *State) GetLatestConfirmedBtcBlock() (*db.BtcBlock, error) {
	s.btcHeadMu.RLock()
	defer s.btcHeadMu.RUnlock()

	var btcBlock db.BtcBlock
	err := s.dbm.GetBtcLightDB().Where("status <> ?", db.BTC_BLOCK_STATUS_UNCONFIRM).Order("height desc").First(&btcBlock).Error
	if err != nil {
		return nil, err
	}
	return &btcBlock, nil
}

func (s *State) queryBtcBlockByHeight(height uint64) (*db.BtcBlock, error) {
	var btcBlock db.BtcBlock
	result := s.dbm.GetBtcLightDB().Where("height = ?", height).First(&btcBlock)
	if result.Error != nil {
		return nil, result.Error
	}
	return &btcBlock, nil
}
