package state

import (
	"fmt"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	log "github.com/sirupsen/logrus"
)

func (s *State) UpdateL2ChainStatus(latestBlock uint64, catchingUp bool) error {
	s.layer2Mu.Lock()
	defer s.layer2Mu.Unlock()

	l2Info := s.layer2State.L2Info
	if l2Info.Syncing != catchingUp {
		l2Info.UpdatedAt = time.Now()
		l2Info.Syncing = catchingUp

		err := s.saveL2Info(l2Info)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *State) UpdateL2InfoEndBlock(block uint64) error {
	s.layer2Mu.Lock()
	defer s.layer2Mu.Unlock()

	l2Info := s.layer2State.L2Info
	if l2Info.Height < block {
		l2Info.UpdatedAt = time.Now()
		l2Info.Height = block

		err := s.saveL2Info(l2Info)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *State) UpdateL2InfoWallet(block uint64, walletType string, walletKey string) error {
	s.layer2Mu.Lock()
	defer s.layer2Mu.Unlock()

	l2Info := s.layer2State.L2Info

	if l2Info.Height <= block {
		l2Info.UpdatedAt = time.Now()
		l2Info.Height = block
		l2Info.DepositKey = fmt.Sprintf("%s,%s", walletType, walletKey)

		err := s.saveL2Info(l2Info)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *State) UpdateL2InfoLatestBtc(block uint64, btcHeight uint64) error {
	s.layer2Mu.Lock()
	defer s.layer2Mu.Unlock()

	l2Info := s.layer2State.L2Info

	if l2Info.Height <= block {
		l2Info.UpdatedAt = time.Now()
		l2Info.Height = block
		l2Info.LatestBtcHeight = btcHeight

		err := s.saveL2Info(l2Info)
		if err != nil {
			return err
		}

		s.layer2State.L2Info = l2Info
	}

	return nil
}

// UpdateL2InfoEpoch update epoch, proposer.
// Given proposer = "", it will only update epoch
func (s *State) UpdateL2InfoEpoch(block uint64, epoch uint, proposer string) error {
	s.layer2Mu.Lock()
	defer s.layer2Mu.Unlock()

	epochVoter := s.layer2State.EpochVoter

	if epochVoter.Height <= block {
		epochVoter.UpdatedAt = time.Now()
		epochVoter.Height = block
		epochVoter.Epoch = epoch
		if proposer != "" {
			epochVoter.Proposer = proposer
		}

		err := s.saveEpochVoter(epochVoter)
		if err != nil {
			return err
		}

		s.layer2State.EpochVoter = epochVoter

		if proposer != "" {
			// TODO call event pulish
		}
	}

	return nil
}

func (s *State) saveEpochVoter(epochVoter *db.EpochVoter) error {
	result := s.dbm.GetL2InfoDB().Save(epochVoter)
	if result.Error != nil {
		log.Errorf("State saveEpochVoter error: %v", result.Error)
		return result.Error
	}
	return nil
}

func (s *State) saveL2Info(l2Info *db.L2Info) error {
	result := s.dbm.GetL2InfoDB().Save(l2Info)
	if result.Error != nil {
		log.Errorf("State saveL2Info error: %v", result.Error)
		return result.Error
	}
	return nil
}