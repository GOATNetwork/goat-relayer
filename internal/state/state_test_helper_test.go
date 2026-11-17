package state

import (
	"gorm.io/gorm"
)

// testDBProvider implements databaseProvider for tests using an in-memory DB.
type testDBProvider struct {
	walletDb *gorm.DB
}

func (m *testDBProvider) GetWalletDB() *gorm.DB {
	return m.walletDb
}

// These methods satisfy the databaseProvider interface; tests reuse the wallet DB.
func (m *testDBProvider) GetL2InfoDB() *gorm.DB {
	return m.walletDb
}

func (m *testDBProvider) GetBtcLightDB() *gorm.DB {
	return m.walletDb
}

func (m *testDBProvider) GetBtcCacheDB() *gorm.DB {
	return m.walletDb
}

// newStateForTest creates a State instance for testing with injected databases.
func newStateForTest(walletDb *gorm.DB) *State {
	return &State{
		EventBus: NewEventBus(),
		dbm:      &testDBProvider{walletDb: walletDb},
	}
}
