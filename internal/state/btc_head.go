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

func (s *State) UpdateConfirmBtcBlock(block *db.BtcBlock) error {
	// TODO
	s.btcHeadChan <- block
	return nil
}

// GetCurrentBtcBlock
func (s *State) GetCurrentBtcBlock() (db.BtcBlock, error) {
	s.btcHeadMu.RLock()
	defer s.btcHeadMu.RUnlock()

	return *s.btcHeadState.Confirmed, nil
}
