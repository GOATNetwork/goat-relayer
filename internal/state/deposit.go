package state

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/types"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

/*
AddUnconfirmDeposit
when utxo scanner detected a new transaction in 1 confirm, save to unconfirmed,
*/
func (s *State) AddUnconfirmDeposit(txHash string, rawTx string, evmAddr string, signVersion uint32, outputIndex int, amount int64) error {
	s.depositMu.Lock()
	defer s.depositMu.Unlock()

	// check if exist, if not save to db
	_, err := s.queryDepositByTxHash(txHash, outputIndex)
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}
	if err == nil {
		// exist height
		return nil
	}

	status := db.DEPOSIT_STATUS_UNCONFIRM

	deposit := &db.Deposit{
		Status:      status,
		Amount:      amount,
		UpdatedAt:   time.Now(),
		TxHash:      txHash,
		RawTx:       rawTx,
		EvmAddr:     evmAddr,
		SignVersion: signVersion,
		OutputIndex: outputIndex,
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
func (s *State) SaveConfirmDeposit(txHash string, rawTx string, evmAddr string, signVersion uint32, outputIndex int, blockHash string, blockHeight uint64, merkleRoot []byte, proofBytes []byte, txIndex int) error {
	s.depositMu.Lock()
	defer s.depositMu.Unlock()

	deposit, err := s.queryDepositByTxHash(txHash, outputIndex)
	status := db.DEPOSIT_STATUS_CONFIRMED

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			deposit = &db.Deposit{
				Status:      status,
				UpdatedAt:   time.Now(),
				BlockHash:   blockHash,
				BlockHeight: blockHeight,
				TxHash:      txHash,
				RawTx:       rawTx,
				EvmAddr:     evmAddr,
				SignVersion: signVersion,
				OutputIndex: outputIndex,
				MerkleRoot:  merkleRoot,
				Proof:       proofBytes,
				TxIndex:     txIndex,
			}
		} else {
			// DB error
			return err
		}
	} else {
		if deposit.Status != db.DEPOSIT_STATUS_PROCESSED {
			deposit.Status = status
			deposit.BlockHash = blockHash
			deposit.BlockHeight = blockHeight
			deposit.TxIndex = txIndex
			deposit.MerkleRoot = merkleRoot
			deposit.Proof = proofBytes
		}
		deposit.UpdatedAt = time.Now()
	}
	if err := s.dbm.GetBtcCacheDB().Save(deposit).Error; err != nil {
		return err
	}
	// remove from unconfirm queue
	for i, ds := range s.depositState.UnconfirmQueue {
		if ds.TxHash == txHash && ds.OutputIndex == outputIndex {
			if i == len(s.depositState.UnconfirmQueue)-1 {
				s.depositState.UnconfirmQueue = s.depositState.UnconfirmQueue[:i]
			} else {
				s.depositState.UnconfirmQueue = append(s.depositState.UnconfirmQueue[:i], s.depositState.UnconfirmQueue[i+1:]...)
			}
			break
		}
	}
	return nil
}

/*
UpdateProcessedDeposit
when utxo committer process a deposit to consensus, save to processed
*/
func (s *State) UpdateProcessedDeposit(txHash string, txout int, evmAddr string) error {
	s.depositMu.Lock()
	defer s.depositMu.Unlock()

	deposit, err := s.queryDepositByTxHash(txHash, txout)
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}
	if err != nil {
		// query db failed, update cache
		deposit = &db.Deposit{
			TxHash:      txHash,
			OutputIndex: txout,
			RawTx:       "",
			EvmAddr:     evmAddr,
			Status:      db.DEPOSIT_STATUS_PROCESSED,
			UpdatedAt:   time.Now(),
		}
	}
	deposit.Status = db.DEPOSIT_STATUS_PROCESSED

	result := s.dbm.GetBtcCacheDB().Save(deposit)
	if result.Error != nil {
		return result.Error
	}

	s.depositState.Latest = *deposit
	// remove from unconfirm queue
	for i, ds := range s.depositState.UnconfirmQueue {
		if ds.TxHash == txHash && ds.OutputIndex == txout {
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
		if ds.TxHash == txHash && ds.OutputIndex == txout {
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
	err := s.dbm.GetBtcCacheDB().Where("id > ? and status = ? and block_hash <> ''", from, db.DEPOSIT_STATUS_CONFIRMED).Order("id asc").Limit(size).Find(&deposits).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	log.Debugf("GetDepositForSign from: %d, deposits found: %d", from, len(deposits))
	return deposits, nil
}

// GetCurrentDeposit get current deposit
func (s *State) GetCurrentDeposit() (db.Deposit, error) {
	s.depositMu.RLock()
	defer s.depositMu.RUnlock()

	return s.depositState.Latest, nil
}

func (s *State) QueryUnConfirmDeposit() ([]db.Deposit, error) {
	s.depositMu.RLock()
	defer s.depositMu.RUnlock()

	var deposit []db.Deposit
	err := s.dbm.GetBtcCacheDB().Where("status = ?", db.DEPOSIT_STATUS_UNCONFIRM).Find(&deposit).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return deposit, nil
}

// QueryBtcBlockDataByHeight query btc block data by height
func (s *State) QueryBtcBlockDataByHeight(height uint64) (db.BtcBlockData, error) {
	var btcBlockData db.BtcBlockData
	result := s.dbm.GetBtcCacheDB().Where("block_height = ?", height).First(&btcBlockData)
	if result.Error != nil {
		return db.BtcBlockData{}, result.Error
	}
	return btcBlockData, nil
}

func (s *State) QueryBtcBlockDataByBlockHashes(blockHashes []string) ([]db.BtcBlockData, error) {
	var btcBlockData []db.BtcBlockData
	result := s.dbm.GetBtcCacheDB().Where("block_hash IN (?)", blockHashes).Find(&btcBlockData)
	if result.Error != nil {
		return nil, result.Error
	}
	return btcBlockData, nil
}

func (s *State) UpdateConfirmedDepositsByBtcHeight(blockHeight uint64, blockHash string) (err error) {
	s.depositMu.Lock()
	defer s.depositMu.Unlock()

	var btcBlockData db.BtcBlockData
	result := s.dbm.GetBtcCacheDB().Where("block_height = ?", blockHeight).Find(&btcBlockData)
	if result.Error != nil {
		return result.Error
	}

	// Save to confirmed while the block has the deposit tx
	if err != nil {
		return err
	}
	txHashes := make([]string, 0)
	err = json.Unmarshal([]byte(btcBlockData.TxHashes), &txHashes)
	if err != nil {
		return err
	}
	for _, deposit := range s.depositState.UnconfirmQueue {
		if !strings.Contains(btcBlockData.TxHashes, deposit.TxHash) {
			continue
		}
		merkleRoot, proofBytes, txIndex, err := types.GenerateSPVProof(deposit.TxHash, txHashes)
		if err != nil {
			return err
		}
		if deposit.Status == db.DEPOSIT_STATUS_UNCONFIRM {
			deposit.Status = db.DEPOSIT_STATUS_CONFIRMED
			deposit.BlockHash = blockHash
			deposit.BlockHeight = blockHeight
			deposit.TxIndex = txIndex
			deposit.MerkleRoot = merkleRoot
			deposit.Proof = proofBytes
			deposit.UpdatedAt = time.Now()
			result := s.dbm.GetBtcCacheDB().Save(deposit)
			if result.Error != nil {
				return result.Error
			}
		}
	}

	return nil
}

func (s *State) queryDepositByTxHash(txHash string, outputIndex int) (*db.Deposit, error) {
	var deposit db.Deposit
	err := s.dbm.GetBtcCacheDB().Where("tx_hash = ? and output_index = ?", txHash, outputIndex).First(&deposit).Error
	if err != nil {
		return nil, err
	}
	return &deposit, nil
}
