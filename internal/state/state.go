package state

import (
	"sync"

	"github.com/goatnetwork/goat-relayer/internal/db"
)

type State struct {
	// Separate mutexes for different sub-modules
	layer2Mu  sync.RWMutex
	btcHeadMu sync.RWMutex
	walletMu  sync.RWMutex

	layer2State  Layer2State
	btcHeadState BtcHeadState
	walletState  WalletState

	btcHeadChan chan *db.BtcBlock
}

// InitializeState initializes the state by reading from the DB
func InitializeState(db *db.DatabaseManager) *State {
	state := &State{}

	// TODO Load layer2State, btcHeadState, walletState from db when start up
	return state
}

// GetL2Info reads the L2Info from memory, using a read lock
func (s *State) GetL2Info() db.L2Info {
	s.layer2Mu.RLock()
	defer s.layer2Mu.RUnlock()

	return *s.layer2State.L2Info
}

func (s *State) SubscribeBtcBlocks() <-chan *db.BtcBlock {
	return s.btcHeadChan
}
