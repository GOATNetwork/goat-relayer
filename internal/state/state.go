package state

import (
	"sync"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type State struct {
	EventBus *EventBus

	dbm *db.DatabaseManager

	// Separate mutexes for different sub-modules
	layer2Mu  sync.RWMutex
	btcHeadMu sync.RWMutex
	walletMu  sync.RWMutex

	layer2State  Layer2State
	btcHeadState BtcHeadState
	walletState  WalletState
}

// InitializeState initializes the state by reading from the DB
func InitializeState(dbm *db.DatabaseManager) *State {
	// Load layer2State, btcHeadState, walletState from db when start up
	var (
		l2Info            db.L2Info
		epochVoter        db.EpochVoter
		currentEpoch      uint64
		voters            []*db.Voter
		voterQueue        []*db.VoterQueue
		latestBtcBlock    db.BtcBlock
		unconfirmBtcQueue []*db.BtcBlock
		sigBtcQueue       []*db.BtcBlock
		sendOrderQueue    []*db.SendOrder
		vinQueue          []*db.Vin
		voutQueue         []*db.Vout
		utxo              *db.Utxo
	)

	l2InfoDb := dbm.GetL2InfoDB()
	btcLightDb := dbm.GetBtcLightDB()
	walletDb := dbm.GetWalletDB()

	loadData := func(db *gorm.DB, dest interface{}, query string, args ...interface{}) {
		if err := db.Where(query, args...).Find(dest).Error; err != nil {
			log.Warnf("Failed to load data: %v", err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(8)

	go func() {
		defer wg.Done()
		if err := l2InfoDb.First(&l2Info).Error; err != nil {
			log.Warnf("Failed to load L2Info: %v", err)

			l2Info = db.L2Info{
				Height:          0,
				Syncing:         false,
				Threshold:       "2/3",
				DepositKey:      "",
				StartBtcHeight:  0,
				LatestBtcHeight: 0,
				UpdatedAt:       time.Now(),
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
		loadData(btcLightDb, &unconfirmBtcQueue, "status in (?)", []string{"unconfirm", "confirmed"})
	}()

	go func() {
		defer wg.Done()
		loadData(btcLightDb, &sigBtcQueue, "status in (?)", []string{"signing", "pending"})
	}()

	go func() {
		defer wg.Done()
		loadData(walletDb, &sendOrderQueue, "status <> ?", "processed")
		loadData(walletDb, &vinQueue, "status <> ?", "processed")
		loadData(walletDb, &voutQueue, "status <> ?", "processed")
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
		},
		walletState: WalletState{
			SendOrderQueue: sendOrderQueue,
			SentVin:        vinQueue,
			SentVout:       voutQueue,
			Utxo:           utxo,
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
