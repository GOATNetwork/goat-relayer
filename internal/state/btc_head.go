package state

import "github.com/goatnetwork/goat-relayer/internal/db"

/*
AddUnconfirmBtcBlock
when btc scanner detected a new block, save to unconfirmed,
proposer will start an off-chain signature
*/
func (s *State) AddUnconfirmBtcBlock(block *db.BtcBlock) error {
	s.btcHeadMu.Lock()
	defer s.btcHeadMu.Unlock()

	// TODO check if exist, if not save to db

	return nil
}

func (s *State) UpdateSigBtcBlock(block *db.BtcBlock, height uint64, hash string) error {
	s.btcHeadMu.Lock()
	defer s.btcHeadMu.Unlock()

	var btcBlock db.BtcBlock
	result := s.dbm.GetBtcLightDB().Where("height = ?", height).FirstOrCreate(&btcBlock)
	if result.Error != nil {
		return result.Error
	}
	s.btcHeadState.SigQueue = append(s.btcHeadState.SigQueue, block)

	return nil
}

func (s *State) UpdateProcessedBtcBlock(block uint64, height uint64, hash string) error {
	s.btcHeadMu.Lock()
	defer s.btcHeadMu.Unlock()

	var btcBlock db.BtcBlock
	result := s.dbm.GetBtcLightDB().Where("height = ?", height).FirstOrCreate(&btcBlock)
	if result.Error != nil {
		return result.Error
	}
	btcBlock.Height = height
	btcBlock.Hash = hash
	btcBlock.Status = "processed"

	result = s.dbm.GetBtcLightDB().Save(&btcBlock)
	if result.Error != nil {
		return result.Error
	}

	s.btcHeadState.Latest = &btcBlock
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

// GetCurrentBtcBlock
func (s *State) GetCurrentBtcBlock() (db.BtcBlock, error) {
	s.btcHeadMu.RLock()
	defer s.btcHeadMu.RUnlock()

	return *s.btcHeadState.Latest, nil
}
