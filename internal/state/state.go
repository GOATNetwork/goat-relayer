package state

import (
	"sync"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/types"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// databaseProvider is the minimal DB interface State depends on.
// Production uses *db.DatabaseManager; tests can inject a stub implementation.
type databaseProvider interface {
	GetL2InfoDB() *gorm.DB
	GetBtcLightDB() *gorm.DB
	GetBtcCacheDB() *gorm.DB
	GetWalletDB() *gorm.DB
}

type StateLoader interface {
	GetL2Info() db.L2Info
	GetUtxo() db.Utxo
	GetDepositState() DepositState
	GetBtcHead() BtcHeadState
}

type State struct {
	EventBus *EventBus

	dbm databaseProvider

	// Separate mutexes for different sub-modules
	layer2Mu  sync.RWMutex
	btcHeadMu sync.RWMutex
	walletMu  sync.RWMutex
	depositMu sync.RWMutex

	layer2State  Layer2State
	btcHeadState BtcHeadState
	walletState  WalletState
	depositState DepositState
}

var (
	_ StateLoader             = (*State)(nil)
	_ WalletStateStore        = (*State)(nil)
	_ WithdrawStateStore      = (*State)(nil)
	_ ConsolidationStateStore = (*State)(nil)
	_ SafeboxTaskStateStore   = (*State)(nil)
)

// InitializeState initializes the state by reading from the DB
func InitializeState(dbm databaseProvider) *State {
	// Load layer2State, btcHeadState, walletState, depositState from db when start up
	var (
		l2Info                db.L2Info
		epochVoter            db.EpochVoter
		currentEpoch          uint64
		voters                []*db.Voter
		voterQueue            []*db.VoterQueue
		latestBtcBlock        db.BtcBlock
		unconfirmBtcQueue     []*db.BtcBlock
		sigBtcQueue           []*db.BtcBlock
		latestDeposit         db.Deposit
		unconfirmDepositQueue []*db.Deposit
		sigDepositQueue       []*db.Deposit
		sendOrderQueue        []*db.SendOrder
		vinQueue              []*db.Vin
		voutQueue             []*db.Vout
		utxo                  *db.Utxo
	)

	l2InfoDb := dbm.GetL2InfoDB()
	btcLightDb := dbm.GetBtcLightDB()
	btcCacheDb := dbm.GetBtcCacheDB()
	walletDb := dbm.GetWalletDB()

	loadData := func(db *gorm.DB, dest interface{}, query string, args ...interface{}) {
		if err := db.Where(query, args...).Find(dest).Error; err != nil {
			log.Warnf("Failed to load data: %v", err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(11)

	go func() {
		defer wg.Done()
		if err := l2InfoDb.First(&l2Info).Error; err != nil {
			log.Warnf("Failed to load L2Info: %v", err)

			l2Info = db.L2Info{
				Height:           0,
				Syncing:          false,
				Threshold:        "2/3",
				DepositKey:       "",
				DepositMagic:     []byte{},
				MinDepositAmount: 1,
				StartBtcHeight:   0,
				LatestBtcHeight:  0,
				UpdatedAt:        time.Now(),
			}
		}
	}()

	go func() {
		defer wg.Done()
		if err := l2InfoDb.First(&epochVoter).Error; err != nil {
			log.Warnf("Failed to load EpochVoter: %v", err)

			epochVoter = db.EpochVoter{
				VoteAddrList: "[]",
				VoteKeyList:  "[]",
				Epoch:        0,
				Height:       0,
				Sequence:     0,
				Proposer:     "",
				UpdatedAt:    time.Now(),
			}
		} else {
			currentEpoch = epochVoter.Epoch
		}
	}()

	go func() {
		defer wg.Done()
		loadData(l2InfoDb, &voters, "")
	}()

	go func() {
		defer wg.Done()
		loadData(l2InfoDb, &voterQueue, "")
	}()

	go func() {
		defer wg.Done()
		if err := btcLightDb.Where("status = ?", "processed").Order("height desc").First(&latestBtcBlock).Error; err != nil {
			log.Warnf("Failed to load latest processed Btc Block: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		loadData(btcLightDb, &unconfirmBtcQueue, "status in (?)", []string{db.BTC_BLOCK_STATUS_UNCONFIRM, db.BTC_BLOCK_STATUS_CONFIRMED})
	}()

	go func() {
		defer wg.Done()
		loadData(btcLightDb, &sigBtcQueue, "status in (?)", []string{db.BTC_BLOCK_STATUS_SIGNING, db.BTC_BLOCK_STATUS_PENDING})
	}()

	go func() {
		defer wg.Done()
		if err := btcCacheDb.Where("status = ?", "processed").Order("id desc").First(&latestDeposit).Error; err != nil {
			log.Warnf("Failed to load latest processed deposit: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		loadData(btcCacheDb, &unconfirmDepositQueue, "status in (?)", []string{db.DEPOSIT_STATUS_UNCONFIRM, db.DEPOSIT_STATUS_CONFIRMED})
	}()

	go func() {
		defer wg.Done()
		loadData(btcCacheDb, &sigDepositQueue, "status in (?)", []string{db.DEPOSIT_STATUS_SIGNING, db.DEPOSIT_STATUS_PENDING})
	}()

	go func() {
		defer wg.Done()
		loadData(walletDb, &sendOrderQueue, "status <> ?", db.ORDER_STATUS_PROCESSED)
		loadData(walletDb, &vinQueue, "status <> ?", db.ORDER_STATUS_PROCESSED)
		loadData(walletDb, &voutQueue, "status <> ?", db.ORDER_STATUS_PROCESSED)
	}()

	wg.Wait()

	log.Infof("State init on startup, l2info: %v, votes: %v, epoch voter: %v, latest btc block: %v", l2Info, voters, epochVoter, latestBtcBlock)

	return &State{
		EventBus: NewEventBus(),

		dbm: dbm,

		layer2State: Layer2State{
			CurrentEpoch: currentEpoch,
			L2Info:       &l2Info,
			EpochVoter:   &epochVoter,
			Voters:       voters,
			VoterQueue:   voterQueue,
		},
		btcHeadState: BtcHeadState{
			Latest:         latestBtcBlock,
			UnconfirmQueue: unconfirmBtcQueue,
			SigQueue:       sigBtcQueue,
			NetworkFee: types.BtcNetworkFee{
				FastestFee:  0,
				HalfHourFee: 0,
				HourFee:     0,
			},
		},
		walletState: WalletState{
			SendOrderQueue: sendOrderQueue,
			SentVin:        vinQueue,
			SentVout:       voutQueue,
			Utxo:           utxo,
		},
		depositState: DepositState{
			Latest:         latestDeposit,
			UnconfirmQueue: unconfirmDepositQueue,
			SigQueue:       sigDepositQueue,
		},
	}
}

// GetL2Info reads the L2Info from memory
func (s *State) GetL2Info() db.L2Info {
	s.layer2Mu.RLock()
	defer s.layer2Mu.RUnlock()

	return *s.layer2State.L2Info
}

// GetUtxo reads the Utxo from memory
func (s *State) GetUtxo() db.Utxo {
	s.layer2Mu.RLock()
	defer s.layer2Mu.RUnlock()

	return *s.walletState.Utxo
}

// GetDepositState reads the DepositState from memory
func (s *State) GetDepositState() DepositState {
	s.depositMu.RLock()
	defer s.depositMu.RUnlock()

	return s.depositState
}

func (s *State) GetBtcHead() BtcHeadState {
	s.btcHeadMu.RLock()
	defer s.btcHeadMu.RUnlock()

	return s.btcHeadState
}
