package state

import (
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	"gorm.io/gorm"
)

/*
AddUnconfirmDeposit
when utxo scanner detected a new transaction in 1 confirm, save to unconfirmed,
*/
func (s *State) AddUnconfirmDeposit(txHash string, rawTx string, evmAddr string) error {
	s.depositMu.Lock()
	defer s.depositMu.Unlock()

	// check if exist, if not save to db
	_, err := s.queryDepositByTxHash(txHash)
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}
	if err == nil {
		// exist height
		return nil
	}

	status := "unconfirm"
	// if height <= s.btcHeadState.Latest.Height {
	// 	status = "processed"
	// }

	deposit := &db.Deposit{
		Status:    status,
		UpdatedAt: time.Now(),
		TxHash:    txHash,
		RawTx:     rawTx,
		EvmAddr:   evmAddr,
	}
	result := s.dbm.GetBtcCacheDB().Save(deposit)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

/*
SaveConfirmDeposit
when utxo scanner detected a new transaction in 6 confirm, save to confirmed
*/
func (s *State) SaveConfirmDeposit(txHash string, rawTx string, evmAddr string) error {
	s.depositMu.Lock()
	defer s.depositMu.Unlock()

	deposit, err := s.queryDepositByTxHash(txHash)
	status := "confirmed"
	// if height <= s.btcHeadState.Latest.Height {
	// 	status = "processed"
	// }

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			deposit = &db.Deposit{
				Status:    status,
				UpdatedAt: time.Now(),
			}
		} else {
			// DB error
			return err
		}
	} else {
		if deposit.Status != "processed" {
			deposit.Status = status
		}
		deposit.UpdatedAt = time.Now()
	}
	result := s.dbm.GetBtcCacheDB().Save(deposit)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

/*
UpdateProcessedDeposit
when utxo committer process a deposit to consensus, save to processed
*/
func (s *State) UpdateProcessedDeposit(txHash string, rawTx string, evmAddr string) error {
	s.depositMu.Lock()
	defer s.depositMu.Unlock()

	deposit, err := s.queryDepositByTxHash(txHash)
	if err != nil {
		// query db failed, update cache
		s.depositState.Latest = db.Deposit{
			TxHash:    txHash,
			RawTx:     rawTx,
			EvmAddr:   evmAddr,
			UpdatedAt: time.Now(),
		}
		return err
	}
	deposit.Status = "processed"

	// TODO update height <= height
	result := s.dbm.GetBtcCacheDB().Save(deposit)
	if result.Error != nil {
		return result.Error
	}

	s.depositState.Latest = *deposit
	for i, bb := range s.depositState.UnconfirmQueue {
		if bb.TxHash == txHash {
			if i == len(s.depositState.UnconfirmQueue)-1 {
				s.depositState.UnconfirmQueue = s.depositState.UnconfirmQueue[:i]
			} else {
				s.depositState.UnconfirmQueue = append(s.depositState.UnconfirmQueue[:i], s.depositState.UnconfirmQueue[i+1:]...)
			}
			break
		}
	}
	for i, bb := range s.depositState.SigQueue {
		if bb.TxHash == txHash {
			if i == len(s.depositState.SigQueue)-1 {
				s.depositState.SigQueue = s.depositState.SigQueue[:i]
			} else {
				s.depositState.SigQueue = append(s.depositState.SigQueue[:i], s.depositState.SigQueue[i+1:]...)
			}
			break
		}
	}

	return nil
}

// GetDepositForSign
func (s *State) GetDepositForSign(size int) ([]*db.Deposit, error) {
	s.depositMu.RLock()
	defer s.depositMu.RUnlock()

	from := s.depositState.Latest.TxHash
	var deposits []*db.Deposit
	// TODO shoud use int to compare
	result := s.dbm.GetBtcCacheDB().Where("tx_hash > ?", from).Order("tx_hash asc").Limit(size).Find(&deposits)
	if result.Error != nil {
		return nil, result.Error
	}
	return deposits, nil
}

// GetCurrentDeposit
func (s *State) GetCurrentDeposit() (db.Deposit, error) {
	s.depositMu.RLock()
	defer s.depositMu.RUnlock()

	return s.depositState.Latest, nil
}

func (s *State) queryDepositByTxHash(txHash string) (*db.Deposit, error) {
	var deposit db.Deposit
	result := s.dbm.GetBtcCacheDB().Where("tx_hash = ?", txHash).First(&deposit)
	if result.Error != nil {
		return nil, result.Error
	}
	return &deposit, nil
}
