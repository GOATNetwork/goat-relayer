package state

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/types"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// UpdateDepositState update the DepositState from memory
func (s *State) UpdateDepositState(deposits []*db.Deposit) {
	s.depositMu.Lock()
	defer s.depositMu.Unlock()

	s.depositState.UnconfirmQueue = deposits
}

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
		CreatedAt:   time.Now(),
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
func (s *State) SaveConfirmDeposit(txHash string, amount int64, rawTx string, evmAddr string, signVersion uint32, outputIndex int, blockHash string, blockHeight uint64, merkleRoot []byte, proofBytes []byte, txIndex int) error {
	s.depositMu.Lock()
	defer s.depositMu.Unlock()

	deposit, err := s.queryDepositByTxHash(txHash, outputIndex)
	status := db.DEPOSIT_STATUS_CONFIRMED

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			deposit = &db.Deposit{
				Status:      status,
				UpdatedAt:   time.Now(),
				Amount:      amount,
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
			deposit.Amount = amount
			deposit.BlockHash = blockHash
			deposit.BlockHeight = blockHeight
			deposit.TxIndex = txIndex
			deposit.MerkleRoot = merkleRoot
			deposit.Proof = proofBytes
			deposit.OutputIndex = outputIndex
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

func (s *State) UpdateSafeboxTaskCancelled(taskId uint64) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		taskDeposit, err := s.queryProcessingSafeboxTaskByTaskId(tx, taskId)
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		if err == gorm.ErrRecordNotFound {
			return fmt.Errorf("safebox task not found")
		}
		taskDeposit.Status = db.TASK_STATUS_CLOSED
		taskDeposit.UpdatedAt = time.Now()
		return tx.Save(&taskDeposit).Error
	})
	return err
}

// CreateSafeboxTask create safebox task
func (s *State) CreateSafeboxTask(taskId uint64, partnerId string, timelockEndTime, deadline, amount uint64, depositAddress, btcAddress, timelockAddress string, btcPubKey, witnessScript []byte) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		_, err := s.queryProcessingSafeboxTaskByEvmAddr(tx, depositAddress)
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		if err == nil {
			return fmt.Errorf("has processing safebox task, task id: %d", taskId)
		}
		taskDeposit := db.SafeboxTask{
			TaskId:          taskId,
			PartnerId:       partnerId,
			DepositAddress:  depositAddress,
			TimelockEndTime: timelockEndTime,
			Deadline:        deadline,
			Amount:          amount,
			Pubkey:          btcPubKey,
			WitnessScript:   witnessScript,
			TimelockAddress: timelockAddress,
			BtcAddress:      btcAddress,
			Status:          db.TASK_STATUS_CREATE,
		}
		return tx.Create(&taskDeposit).Error
	})
	return err
}

func (s *State) UpdateSafeboxTaskInitOK(taskId uint64, timelockTxid string, timelockOutIndex uint64) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		taskDeposit, err := s.queryProcessingSafeboxTaskByTaskId(tx, taskId)
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		if err == gorm.ErrRecordNotFound {
			return fmt.Errorf("task deposit not found")
		}
		if taskDeposit.Status != db.TASK_STATUS_INIT && taskDeposit.Status != db.TASK_STATUS_RECEIVED_OK && taskDeposit.Status != db.TASK_STATUS_RECEIVED && taskDeposit.Status != db.TASK_STATUS_CREATE {
			return fmt.Errorf("task deposit status is not received or create")
		}
		taskDeposit.TimelockTxid = timelockTxid
		taskDeposit.TimelockOutIndex = timelockOutIndex
		taskDeposit.Status = db.TASK_STATUS_INIT_OK
		taskDeposit.UpdatedAt = time.Now()
		err = tx.Save(&taskDeposit).Error
		if err != nil {
			return err
		}
		// update sendorder status to init
		order, err := s.getOrderByTxid(tx, timelockTxid)
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		if order == nil {
			return nil
		}
		if order.Status == db.ORDER_STATUS_CONFIRMED || order.Status == db.ORDER_STATUS_PROCESSED || order.Status == db.ORDER_STATUS_CLOSED {
			return nil
		}
		order.Status = db.ORDER_STATUS_INIT
		order.UpdatedAt = time.Now()
		err = s.saveOrder(tx, order)
		if err != nil {
			return err
		}
		err = s.updateOtherStatusByOrder(tx, order.OrderId, db.ORDER_STATUS_INIT, true)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

func (s *State) UpdateSafeboxTaskInit(timelockAddress string, timelockTxid string, timelockOutIndex uint64) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		taskDeposit, err := s.queryProcessingSafeboxTaskByTimelockAddress(tx, timelockAddress)
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		if err == gorm.ErrRecordNotFound {
			return fmt.Errorf("task deposit not found")
		}
		if taskDeposit.Status != db.TASK_STATUS_RECEIVED_OK && taskDeposit.Status != db.TASK_STATUS_RECEIVED && taskDeposit.Status != db.TASK_STATUS_CREATE {
			return fmt.Errorf("task deposit status is not received or create")
		}
		taskDeposit.TimelockTxid = timelockTxid
		taskDeposit.TimelockOutIndex = timelockOutIndex
		taskDeposit.Status = db.TASK_STATUS_INIT
		taskDeposit.UpdatedAt = time.Now()
		return tx.Save(&taskDeposit).Error
	})
	return err
}

// UpdateSafeboxTaskReceivedOK update safebox task after received consensus event from contract
func (s *State) UpdateSafeboxTaskReceivedOK(taskId uint64, fundingTxHash string, txOut uint64) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		taskDeposit, err := s.queryProcessingSafeboxTaskByTaskId(tx, taskId)
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		if err == gorm.ErrRecordNotFound {
			return fmt.Errorf("task deposit not found")
		}
		if taskDeposit.Status != db.TASK_STATUS_RECEIVED && taskDeposit.Status != db.TASK_STATUS_CREATE {
			return fmt.Errorf("task deposit status is not received or create")
		}
		taskDeposit.FundingTxid = fundingTxHash
		taskDeposit.FundingOutIndex = txOut
		taskDeposit.Status = db.TASK_STATUS_RECEIVED_OK
		taskDeposit.UpdatedAt = time.Now()
		return tx.Save(&taskDeposit).Error
	})
	return err
}

func (s *State) UpdateSafeboxTaskReceived(txid, evmAddr string, txout uint64, amount uint64) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		taskDeposit, err := s.queryProcessingSafeboxTaskByEvmAddr(tx, evmAddr)
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		// should not return error if task deposit not found
		if err == gorm.ErrRecordNotFound {
			return nil
		}

		// check if deadline is over
		if time.Now().Unix() > int64(taskDeposit.Deadline) {
			log.Info("found a task deposit with deadline over, txid: %s, txout: %d, amount: %s, evmAddr: %s", txid, txout, amount, evmAddr)
			// close it
			taskDeposit.Status = db.TASK_STATUS_CLOSED
			taskDeposit.UpdatedAt = time.Now()
			return tx.Save(&taskDeposit).Error
		}

		// check if amount is enough
		if amount != taskDeposit.Amount {
			// not match, ignore
			return fmt.Errorf("amount not match, task deposit amount: %d, amount: %d", taskDeposit.Amount, amount)
		}

		taskDeposit.Status = db.TASK_STATUS_RECEIVED
		taskDeposit.FundingTxid = txid
		taskDeposit.FundingOutIndex = txout
		taskDeposit.UpdatedAt = time.Now()
		return tx.Save(&taskDeposit).Error
	})
	return err
}

// GetDepositForSign get deposits for sign
func (s *State) GetDepositForSign(size int, processedHeight uint64) ([]*db.Deposit, error) {
	s.depositMu.RLock()
	defer s.depositMu.RUnlock()

	var deposits []*db.Deposit
	err := s.dbm.GetBtcCacheDB().Where("status = ? and amount >= ? and block_hash <> '' and tx_index >= 0 and block_height <= ?", db.DEPOSIT_STATUS_CONFIRMED, s.layer2State.L2Info.MinDepositAmount, processedHeight).Order("id asc").Limit(size).Find(&deposits).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	log.Debugf("GetDepositForSign, deposits found: %d", len(deposits))
	return deposits, nil
}

// GetCurrentDeposit get current deposit
func (s *State) GetCurrentDeposit() (db.Deposit, error) {
	s.depositMu.RLock()
	defer s.depositMu.RUnlock()

	return s.depositState.Latest, nil
}

func (s *State) QueryUnConfirmDeposit(startId uint64, size int) ([]db.Deposit, error) {
	s.depositMu.RLock()
	defer s.depositMu.RUnlock()

	var deposit []db.Deposit
	err := s.dbm.GetBtcCacheDB().Where("status = ? and id > ? and created_at > ?",
		db.DEPOSIT_STATUS_UNCONFIRM, startId, time.Now().Add(-time.Hour*72)).Order("id asc").Limit(size).Find(&deposit).Error
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

func (s *State) queryProcessingSafeboxTaskByTimelockAddress(tx *gorm.DB, timelockAddress string) (*db.SafeboxTask, error) {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	var task db.SafeboxTask
	status := []string{db.TASK_STATUS_CONFIRMED_OK, db.TASK_STATUS_COMPLETED, db.TASK_STATUS_CLOSED}
	err := tx.Where("timelock_address = ? and status NOT IN (?)", timelockAddress, status).First(&task).Error
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *State) queryProcessingSafeboxTaskByTaskId(tx *gorm.DB, taskId uint64) (*db.SafeboxTask, error) {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	var task db.SafeboxTask
	status := []string{db.TASK_STATUS_CONFIRMED_OK, db.TASK_STATUS_COMPLETED, db.TASK_STATUS_CLOSED}
	err := tx.Where("task_id = ? and status NOT IN (?)", taskId, status).First(&task).Error
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *State) queryProcessingSafeboxTaskByEvmAddr(tx *gorm.DB, evmAddr string) (*db.SafeboxTask, error) {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	var task db.SafeboxTask
	status := []string{db.TASK_STATUS_CONFIRMED_OK, db.TASK_STATUS_COMPLETED, db.TASK_STATUS_CLOSED}
	err := tx.Where("deposit_address = ? and status NOT IN (?)", evmAddr, status).First(&task).Error
	if err != nil {
		return nil, err
	}
	return &task, nil
}
