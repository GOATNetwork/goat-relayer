package utxo

import (
	"context"

	"github.com/goatnetwork/goat-relayer/internal/bls"

	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"gorm.io/gorm"
)

// Deposit struct
type Deposit struct {
	state   *state.State
	signer  *bls.Signer
	cacheDb *gorm.DB
	lightDb *gorm.DB

	confirmDepositCh chan interface{}
}

func NewDeposit(st *state.State, signer *bls.Signer, dbm *db.DatabaseManager) *Deposit {
	cacheDb := dbm.GetBtcCacheDB()
	lightDb := dbm.GetBtcLightDB()
	return &Deposit{
		state:            st,
		signer:           signer,
		cacheDb:          cacheDb,
		lightDb:          lightDb,
		confirmDepositCh: make(chan interface{}, 100),
	}
}

func (d *Deposit) Start(ctx context.Context) {
	d.state.EventBus.Subscribe(state.DepositReceive, d.confirmDepositCh)
	// TODO wait for btc & goat chain complete blocks sync
	go d.depositLoop(ctx)
	go d.processConfirmedDeposit(ctx)
}
