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
func (s *State) AddUnconfirmDeposit(txHash string, rawTx string, evmAddr string, signVersion uint32) error {
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

	deposit := &db.Deposit{
		Status:      status,
		UpdatedAt:   time.Now(),
		TxHash:      txHash,
		RawTx:       rawTx,
		EvmAddr:     evmAddr,
		SignVersion: signVersion,
	}
	result := s.dbm.GetBtcCacheDB().Save(deposit)
	if result.Error != nil {
		return result.Error
	}

	s.depositState.UnconfirmQueue = append(s.depositState.UnconfirmQueue, deposit)

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

	result := s.dbm.GetBtcCacheDB().Save(deposit)
	if result.Error != nil {
		return result.Error
	}

	s.depositState.Latest = *deposit
	// remove from unconfirm queue
	for i, ds := range s.depositState.UnconfirmQueue {
		if ds.TxHash == txHash {
			if i == len(s.depositState.UnconfirmQueue)-1 {
				s.depositState.UnconfirmQueue = s.depositState.UnconfirmQueue[:i]
			} else {
				s.depositState.UnconfirmQueue = append(s.depositState.UnconfirmQueue[:i], s.depositState.UnconfirmQueue[i+1:]...)
			}
			break
		}
	}
	// remove from sig queue
	for i, ds := range s.depositState.SigQueue {
		if ds.TxHash == txHash {
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

// GetDepositForSign get deposits for sign
func (s *State) GetDepositForSign(size int) ([]*db.Deposit, error) {
	s.depositMu.RLock()
	defer s.depositMu.RUnlock()

	from := s.depositState.Latest.ID
	var deposits []*db.Deposit
	result := s.dbm.GetBtcCacheDB().Where("id > ?", from).Order("id asc").Limit(size).Find(&deposits)
	if result.Error != nil {
		return nil, result.Error
	}
	return deposits, nil
}

// GetCurrentDeposit get current deposit
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

func (s *State) QueryUnConfirmDeposit() ([]db.Deposit, error) {
	var deposit []db.Deposit
	result := s.dbm.GetBtcCacheDB().Where("status = ?", "unconfirm").Find(&deposit)
	if result.Error != nil {
		return nil, result.Error
	}
	return deposit, nil
}

func (s *State) QueryBlockByTxHash(txHash string) (block *db.BtcBlockData, err error) {
	var btcTxOutput db.BtcTXOutput
	if err := s.dbm.GetBtcCacheDB().Where("tx_hash = ?", txHash).First(&btcTxOutput).Error; err != nil {
		return nil, err
	}

	var btcBlockData db.BtcBlockData
	if err := s.dbm.GetBtcCacheDB().Where("id = ?", btcTxOutput.BlockID).First(&btcBlockData).Error; err != nil {
		return nil, err
	}

	var btcBlock db.BtcBlock
	if err := s.dbm.GetBtcLightDB().Where("height = ? and status = ?", btcBlockData.BlockHeight, "processed").First(&btcBlock).Error; err != nil {
		return nil, err
	}
	// TODO check block hash by pkscript
	// blockHashBytes := btcTxOutput.PkScript[:32] // Assuming the block hash is the first 32 bytes of PkScript
	// blockHash, err := chainhash.NewHash(blockHashBytes)
	// if err != nil {
	// 	return nil, err
	// }

	// // checkout block
	// if btcBlockData.BlockHash != blockHash.String() {
	// 	return nil, errors.New("block hash mismatch")
	// }

	return &btcBlockData, nil
}
