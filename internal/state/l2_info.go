package state

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	log "github.com/sirupsen/logrus"
)

func (s *State) GetEpochVoter() db.EpochVoter {
	s.layer2Mu.RLock()
	defer s.layer2Mu.RUnlock()

	return *s.layer2State.EpochVoter
}

func (s *State) GetDepositKeyByBtcBlock(block uint64) (*db.DepositPubKey, error) {
	s.layer2Mu.RLock()
	defer s.layer2Mu.RUnlock()

	sql := "pub_type='secp256k1'"
	if block > 0 {
		sql += " and " + fmt.Sprintf("btc_height<=%d", block)
	}
	var pubKey db.DepositPubKey
	result := s.dbm.GetL2InfoDB().Where(sql).Order("id DESC").First(&pubKey)
	if result.Error != nil {
		return nil, result.Error
	}
	return &pubKey, nil
}

func (s *State) UpdateL2ChainStatus(latestBlock, l2Confirmations uint64, catchingUp bool) error {
	s.layer2Mu.Lock()
	defer s.layer2Mu.Unlock()

	l2Info := s.layer2State.L2Info
	if !catchingUp && l2Info.Height+l2Confirmations+5 < latestBlock {
		// if cache height + 1 + 4 < latest, mark it as catching up
		// plus 4 to compatible network delay when voter sign
		log.Debugf("State UpdateL2ChainStatus marks catching up, cache height: %d, chain height: %d", l2Info.Height, latestBlock)
		catchingUp = true
	}
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

func (s *State) UpdateL2InfoFirstBlock(block uint64, info *db.L2Info, voters []*db.Voter, epoch, sequence uint64, proposer string) error {
	s.layer2Mu.Lock()
	defer s.layer2Mu.Unlock()

	err := s.saveVoters(voters)
	if err != nil {
		log.Errorf("Save voters error: %v", err)
		return err
	}
	s.layer2State.Voters = voters

	err = s.saveL2Info(info)
	if err != nil {
		log.Errorf("Save L2 info error: %v", err)
		return err
	}

	epochVoter := s.layer2State.EpochVoter
	if epochVoter.Height <= block {
		epochVoter.UpdatedAt = time.Now()
		epochVoter.Height = block
		epochVoter.Epoch = epoch
		epochVoter.Sequence = sequence
		epochVoter.Proposer = proposer

		addrArray := make([]string, 0)
		keyArray := make([]string, 0)
		for _, voter := range voters {
			addrArray = append(addrArray, voter.VoteAddr)
			keyArray = append(keyArray, voter.VoteKey)
		}
		epochVoter.VoteAddrList = strings.Join(addrArray, ",")
		epochVoter.VoteKeyList = strings.Join(keyArray, ",")

		err := s.saveEpochVoter(epochVoter)
		if err != nil {
			return err
		}

		s.layer2State.EpochVoter = epochVoter
		s.layer2State.CurrentEpoch = epoch
	}
	return nil
}

func (s *State) UpdateL2InfoVoters(block, epoch, sequence uint64, proposer string, voters []*db.Voter) error {
	s.layer2Mu.Lock()
	defer s.layer2Mu.Unlock()

	err := s.saveVoters(voters)
	if err != nil {
		log.Errorf("Save voters error: %v", err)
		return err
	}
	s.layer2State.Voters = voters

	epochVoter := s.layer2State.EpochVoter
	if epochVoter.Height <= block {
		epochVoter.UpdatedAt = time.Now()
		epochVoter.Height = block
		epochVoter.Epoch = epoch
		epochVoter.Sequence = sequence
		epochVoter.Proposer = proposer

		addrArray := make([]string, 0)
		keyArray := make([]string, 0)
		for _, voter := range voters {
			addrArray = append(addrArray, voter.VoteAddr)
			keyArray = append(keyArray, voter.VoteKey)
		}
		epochVoter.VoteAddrList = strings.Join(addrArray, ",")
		epochVoter.VoteKeyList = strings.Join(keyArray, ",")

		err := s.saveEpochVoter(epochVoter)
		if err != nil {
			return err
		}

		s.layer2State.EpochVoter = epochVoter
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

		// save BTC_HEIGHT <-> wallet_key
		err = s.savePubKey(&db.DepositPubKey{
			PubType:   walletType,
			PubKey:    walletKey,
			BtcHeight: l2Info.LatestBtcHeight,
			UpdatedAt: time.Now(),
		})
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
	}

	return nil
}

// UpdateL2InfoEpoch update epoch, proposer.
// Given proposer = "", it will only update epoch
func (s *State) UpdateL2InfoEpoch(block uint64, epoch uint64, proposer string) error {
	s.layer2Mu.Lock()
	defer s.layer2Mu.Unlock()

	epochVoter := s.layer2State.EpochVoter

	if epochVoter.Height <= block {
		epochVoter.UpdatedAt = time.Now()
		epochVoter.Height = block
		epochVoter.Epoch = epoch
		if proposer != "" {
			epochVoter.Proposer = proposer

			// TODO check the voters change or not?
		}

		err := s.saveEpochVoter(epochVoter)
		if err != nil {
			return err
		}

		s.layer2State.EpochVoter = epochVoter
		s.layer2State.CurrentEpoch = epoch

		if proposer != "" {
			// TODO call event pulish
		}
	}

	return nil
}

func (s *State) UpdateL2InfoSequence(block uint64, sequence uint64) error {
	s.layer2Mu.Lock()
	defer s.layer2Mu.Unlock()

	epochVoter := s.layer2State.EpochVoter

	if epochVoter.Height <= block {
		epochVoter.UpdatedAt = time.Now()
		epochVoter.Height = block
		epochVoter.Sequence = sequence + 1

		err := s.saveEpochVoter(epochVoter)
		if err != nil {
			return err
		}

		s.layer2State.EpochVoter = epochVoter
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
	s.layer2State.L2Info = l2Info
	return nil
}

func (s *State) saveVoters(voters []*db.Voter) error {
	s.dbm.GetL2InfoDB().Where("1 = 1").Delete(&db.Voter{})
	// voters is empty when single proposer node
	if len(voters) == 0 {
		return nil
	}
	result := s.dbm.GetL2InfoDB().Save(voters)
	if result.Error != nil {
		log.Errorf("State saveVoters error: %v", result.Error)
		return result.Error
	}
	return nil
}

func (s *State) savePubKey(pubKey *db.DepositPubKey) error {
	result := s.dbm.GetL2InfoDB().Save(pubKey)
	if result.Error != nil {
		log.Errorf("State savePubKey error: %v", result.Error)
		return result.Error
	}
	return nil
}

func (s *State) GetPubKey() ([]byte, error) {
	l2Info := s.GetL2Info()

	var err error
	var pubKey []byte
	if l2Info.DepositKey == "," || l2Info.DepositKey == "" {
		depositPubKey, err := s.GetDepositKeyByBtcBlock(0)
		if err != nil {
			return nil, err
		}
		pubKey, err = base64.StdEncoding.DecodeString(depositPubKey.PubKey)
		if err != nil {
			return nil, err
		}
	} else {
		pubKeyStr := strings.Split(l2Info.DepositKey, ",")[1]
		pubKey, err = base64.StdEncoding.DecodeString(pubKeyStr)
		if err != nil {
			return nil, err
		}
	}

	return pubKey, nil
}
