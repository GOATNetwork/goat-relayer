package state

import (
	"errors"
	"fmt"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type WithdrawStateStore interface {
	CleanProcessingWithdraw() error
	CloseWithdrawByRequestId(requestId uint64, reason string) error
	CreateWithdrawal(sender string, receiver string, block, id, txPrice, amount uint64) error
	CreateSendOrder(order *db.SendOrder, selectedUtxos []*db.Utxo, selectedWithdraws []*db.Withdraw, safeboxTasks []*db.SafeboxTask, vins []*db.Vin, vouts []*db.Vout, isProposer bool) error
	RecoverSendOrder(order *db.SendOrder, vins []*db.Vin, vouts []*db.Vout, withdrawIds []uint64) error
	UpdateWithdrawInitialized(txid string, pid uint64) error
	UpdateWithdrawFinalized(txid string, pid uint64) error
	UpdateWithdrawReplace(id, txPrice uint64) error
	UpdateWithdrawCanceling(id uint64) error
	UpdateSendOrderInitlized(txid string, externalTxId string) error
	UpdateSendOrderPending(txid string, externalTxId string, withdrawIds []uint64, sendOrder *db.SendOrder, utxos []*db.Utxo, vins []*db.Vin, vouts []*db.Vout) error
	UpdateSendOrderConfirmed(txid string, blockHeight uint64) error
	GetWithdrawsCanStart() ([]*db.Withdraw, error)
	GetWithdrawsCanceling() ([]*db.Withdraw, error)
	GetWithdrawsByOrderId(orderId string) ([]*db.Withdraw, error)
	GetSendOrderInitlized() ([]*db.SendOrder, error)
	GetSendOrderPending(limit int) ([]*db.SendOrder, error)
	GetLatestWithdrawSendOrderConfirmed() (*db.SendOrder, error)
}

// CreateWithdrawal, when a new withdrawal request is detected, save to unconfirmed
//
// Parameters:
//
//	address - to btc p2pkh, p2wpkh address
//	block - goat block
//	id - request id
//	txPrice - user set txPrice for withdraw
//	amount - user request withdraw amount of btc (unit satoshis)
func (s *State) CreateWithdrawal(sender string, receiver string, block, id, txPrice, amount uint64) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	// check if exist, if not save to db
	_, err := s.getWithdrawByRequestId(nil, id)
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}
	if err == nil {
		// exist
		return nil
	}

	withdraw := &db.Withdraw{
		RequestId: id,
		GoatBlock: block,
		From:      sender,
		To:        receiver,
		Amount:    amount,
		TxPrice:   txPrice,
		TxFee:     0,
		Status:    db.WITHDRAW_STATUS_CREATE,
		OrderId:   "",
		Reason:    "",
		UpdatedAt: time.Now(),
		CreatedAt: time.Now(),
	}

	return s.saveWithdraw(nil, withdraw)
}

// CreateSendOrder, create a send order when start withdrawal or consolidation
func (s *State) CreateSendOrder(order *db.SendOrder, selectedUtxos []*db.Utxo, selectedWithdraws []*db.Withdraw, safeboxTasks []*db.SafeboxTask, vins []*db.Vin, vouts []*db.Vout, isProposer bool) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		err := s.saveOrder(tx, order)
		if err != nil {
			return err
		}

		if err = tx.Create(&vins).Error; err != nil {
			return err
		}

		if err = tx.Create(&vouts).Error; err != nil {
			return err
		}

		// update utxo status
		for _, utxo := range selectedUtxos {
			var utxoInDb db.Utxo
			if err = tx.Where("txid = ? and out_index = ?", utxo.Txid, utxo.OutIndex).Order("id desc").First(&utxoInDb).Error; err != nil {
				return err
			}
			// utxo status can not be make withdrawal or consolidation
			// don't need to check proposer or voter
			// both role should clean processing withdraw
			if utxoInDb.Status == db.UTXO_STATUS_UNCONFIRM || utxoInDb.Status == db.UTXO_STATUS_PENDING || utxoInDb.Status == db.UTXO_STATUS_SPENT {
				return fmt.Errorf("utxo status can not be make withdrawal or consolidation, utxo id: %d, status: %s", utxoInDb.ID, utxoInDb.Status)
			}
			err = tx.Model(&db.Utxo{}).Where("id = ?", utxoInDb.ID).Updates(&db.Utxo{Status: db.UTXO_STATUS_PENDING, UpdatedAt: time.Now()}).Error
			if err != nil {
				log.Errorf("State CreateSendOrder update utxo records error: %v", err)
				return err
			}
		}

		// update safebox task status
		if order.OrderType == db.ORDER_TYPE_SAFEBOX {
			for _, task := range safeboxTasks {
				var taskInDb db.SafeboxTask
				if err = tx.Where("task_id = ?", task.TaskId).First(&taskInDb).Error; err != nil {
					return err
				}
				if isProposer {
					if taskInDb.Status != db.TASK_STATUS_RECEIVED_OK {
						return fmt.Errorf("safebox task status can not be make timelock tx, task id: %d, status: %s", taskInDb.TaskId, taskInDb.Status)
					}
					err = tx.Model(&db.SafeboxTask{}).Where("id = ?", taskInDb.ID).Updates(&db.SafeboxTask{
						Status:       db.TASK_STATUS_INIT,
						OrderId:      order.OrderId,
						TimelockTxid: order.Txid,
						UpdatedAt:    time.Now(),
					}).Error
					if err != nil {
						log.Errorf("State CreateSendOrder update safebox task records error: %v", err)
						return err
					}
				} else {
					// voter perhaps receipt multiple orders with the same withdraw
					if taskInDb.Status != db.TASK_STATUS_RECEIVED_OK && taskInDb.Status != db.TASK_STATUS_INIT {
						return fmt.Errorf("safebox task status can not be make timelock tx, task id: %d, status: %s", taskInDb.TaskId, taskInDb.Status)
					}
					if taskInDb.Status == db.TASK_STATUS_RECEIVED_OK || taskInDb.Status == db.TASK_STATUS_INIT {
						err = tx.Model(&db.SafeboxTask{}).Where("id = ?", taskInDb.ID).Updates(&db.SafeboxTask{
							Status:       db.TASK_STATUS_INIT,
							OrderId:      order.OrderId,
							TimelockTxid: order.Txid,
							UpdatedAt:    time.Now(),
						}).Error
						if err != nil {
							log.Errorf("State CreateSendOrder update safebox task records error: %v", err)
							return err
						}
					}
				}
			}
		}

		// update withdraw status
		if order.OrderType == db.ORDER_TYPE_WITHDRAWAL {
			for _, withdraw := range selectedWithdraws {
				var withdrawInDb db.Withdraw
				if err = tx.Where("request_id = ?", withdraw.RequestId).First(&withdrawInDb).Error; err != nil {
					return err
				}
				if isProposer {
					if withdrawInDb.Status != db.WITHDRAW_STATUS_CREATE {
						return fmt.Errorf("withdraw status can not be make withdrawal, id: %d, status: %s", withdrawInDb.ID, withdrawInDb.Status)
					}
					err = tx.Model(&db.Withdraw{}).Where("id = ?", withdrawInDb.ID).Updates(&db.Withdraw{
						Status:    db.WITHDRAW_STATUS_AGGREGATING,
						OrderId:   order.OrderId,
						Txid:      order.Txid,
						UpdatedAt: time.Now(),
					}).Error
					if err != nil {
						log.Errorf("State CreateSendOrder update withdraw records error: %v", err)
						return err
					}
				} else {
					// voter perhaps receipt multiple orders with the same withdraw
					if withdrawInDb.Status != db.WITHDRAW_STATUS_CREATE && withdrawInDb.Status != db.WITHDRAW_STATUS_AGGREGATING {
						return fmt.Errorf("withdraw status can not be make withdrawal, id: %d, status: %s", withdrawInDb.ID, withdrawInDb.Status)
					}
					if withdrawInDb.Status == db.WITHDRAW_STATUS_CREATE || withdrawInDb.Status == db.WITHDRAW_STATUS_AGGREGATING {
						err = tx.Model(&db.Withdraw{}).Where("id = ?", withdrawInDb.ID).Updates(&db.Withdraw{
							Status:    db.WITHDRAW_STATUS_AGGREGATING,
							OrderId:   order.OrderId,
							Txid:      order.Txid,
							UpdatedAt: time.Now(),
						}).Error
						if err != nil {
							log.Errorf("State CreateSendOrder update withdraw records error: %v", err)
							return err
						}
					}
				}
			}
		}

		return nil
	})
	return err
}

// RecoverSendOrder, recover send order when layer2 read MsgInitalizeWithdrawal tx
func (s *State) RecoverSendOrder(order *db.SendOrder, vins []*db.Vin, vouts []*db.Vout, withdrawIds []uint64) error {
	// 1. check order, if exists, return
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		// 2. check order, if exists, return
		orderInDb, err := s.getOrderByTxidAndStatuses(tx, order.Txid, db.ORDER_STATUS_INIT, db.ORDER_STATUS_AGGREGATING)
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		if orderInDb != nil {
			return nil
		}

		// 2. update withdraw status to aggregating
		for _, withdrawId := range withdrawIds {
			withdrawInDb, err := s.getWithdrawByRequestId(tx, withdrawId)
			if err != nil && err != gorm.ErrRecordNotFound {
				return err
			}
			if err == gorm.ErrRecordNotFound {
				continue
			}
			if withdrawInDb.Status != db.WITHDRAW_STATUS_CREATE && withdrawInDb.Status != db.WITHDRAW_STATUS_AGGREGATING {
				continue
			}
			withdrawInDb.Status = db.WITHDRAW_STATUS_INIT
			withdrawInDb.OrderId = order.OrderId
			withdrawInDb.Txid = order.Txid
			withdrawInDb.UpdatedAt = time.Now()
			err = s.saveWithdraw(tx, withdrawInDb)
			if err != nil {
				return err
			}
		}

		// 3. update utxo status if find
		for _, vin := range vins {
			var utxoInDb db.Utxo
			err := tx.Where("txid = ? and out_index = ?", vin.Txid, vin.OutIndex).Order("id desc").First(&utxoInDb).Error
			if err != nil && err != gorm.ErrRecordNotFound {
				return err
			}
			if err == gorm.ErrRecordNotFound {
				continue
			}
			if utxoInDb.Status == db.UTXO_STATUS_PENDING || utxoInDb.Status == db.UTXO_STATUS_SPENT {
				continue
			}
			err = tx.Model(&db.Utxo{}).Where("id = ?", utxoInDb.ID).Updates(&db.Utxo{Status: db.UTXO_STATUS_PENDING, UpdatedAt: time.Now()}).Error
			if err != nil {
				log.Errorf("State RecoverSendOrder update utxo records error: %v", err)
				return err
			}
			// set receiver type to vin
			vin.ReceiverType = utxoInDb.ReceiverType
		}

		// 4. save order
		err = s.saveOrder(tx, order)
		if err != nil {
			return err
		}

		// 5. vins, vouts
		if err = tx.Create(&vins).Error; err != nil {
			return err
		}

		if err = tx.Create(&vouts).Error; err != nil {
			return err
		}

		return nil
	})
	return err
}

func (s *State) UpdateWithdrawReplace(id, txPrice uint64) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	withdraw, err := s.getWithdrawByRequestId(nil, id)
	if err != nil {
		return err
	}
	if withdraw.Status != db.WITHDRAW_STATUS_CREATE && withdraw.Status != db.WITHDRAW_STATUS_AGGREGATING {
		// ignore if it is not create status
		// it is hard to update after start withdraw sig program
		return nil
	}

	withdraw.TxPrice = txPrice
	withdraw.UpdatedAt = time.Now()

	// RBF will with higher txPrice, so no need to notify stop aggregating

	return s.saveWithdraw(nil, withdraw)
}

// UpdateWithdrawCanceling, update withdraw status to canceling
func (s *State) UpdateWithdrawCanceling(id uint64) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	withdraw, err := s.getWithdrawByRequestId(nil, id)
	if err != nil {
		return err
	}
	if withdraw.Status != db.WITHDRAW_STATUS_CREATE && withdraw.Status != db.WITHDRAW_STATUS_AGGREGATING {
		// ignore if it is not create status
		// it is hard to update after start withdraw sig program
		return nil
	}

	withdraw.Status = db.WITHDRAW_STATUS_CANCELING
	withdraw.UpdatedAt = time.Now()

	// NOTE check stop aggregating order if there is aggregating status withdraw, set to closed

	return s.saveWithdraw(nil, withdraw)
}

// UpdateWithdrawCanceled, update withdraw status to closed
func (s *State) UpdateWithdrawCanceled(id uint64) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	withdraw, err := s.getWithdrawByRequestId(nil, id)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			// ignore
			log.Warnf("State UpdateWithdrawCanceled not found withdraw by request id: %d", id)
			return nil
		}
		return err
	}

	withdraw.Status = db.WITHDRAW_STATUS_CLOSED
	withdraw.Reason = "canceled"
	withdraw.UpdatedAt = time.Now()
	return s.saveWithdraw(nil, withdraw)
}

// UpdateSendOrderInitlized
// when a withdrawal or consolidation request is confirmed, save to confirmed
func (s *State) UpdateSendOrderInitlized(txid string, externalTxId string) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		order, err := s.getOrderByTxid(tx, txid)
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
		order.ExternalTxId = externalTxId
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

// UpdateSendOrderPending
// when a withdrawal or consolidation request is confirmed, save to confirmed
func (s *State) UpdateSendOrderPending(txid string, externalTxId string, withdrawIds []uint64, sendOrder *db.SendOrder, utxos []*db.Utxo, vins []*db.Vin, vouts []*db.Vout) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		order, err := s.getOrderByTxid(tx, txid)
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		if order == nil || err == gorm.ErrRecordNotFound {
			// recover order, vins, vouts
			if sendOrder == nil || len(utxos) == 0 || len(vins) == 0 || len(vouts) == 0 {
				return errors.New("send order, utxos, vins, vouts is nil")
			}
			sendOrder.ID = 0
			order = sendOrder
			err = s.saveOrder(tx, order)
			if err != nil {
				return err
			}
			for _, utxo := range utxos {
				utxoInDb, err := s.getUtxo(tx, utxo.Txid, utxo.OutIndex)
				if err != nil {
					return err
				}
				if utxoInDb.Status == db.UTXO_STATUS_PENDING || utxoInDb.Status == db.UTXO_STATUS_SPENT || utxoInDb.Status == db.UTXO_STATUS_UNCONFIRM {
					return errors.New("utxo status is not valid")
				}
				utxoInDb.Status = db.UTXO_STATUS_PENDING
				utxoInDb.UpdatedAt = time.Now()
				err = s.saveUtxo(tx, utxoInDb)
				if err != nil {
					return err
				}

			}
			for _, vin := range vins {
				vin.ID = 0
				vin.OrderId = sendOrder.OrderId
				err = s.saveVin(tx, vin)
				if err != nil {
					return err
				}
			}
			for _, withdrawId := range withdrawIds {
				withdrawInDb, err := s.getWithdrawByRequestId(tx, withdrawId)
				if err != nil && err != gorm.ErrRecordNotFound {
					return err
				}
				if withdrawInDb.Status == db.WITHDRAW_STATUS_AGGREGATING || withdrawInDb.Status == db.WITHDRAW_STATUS_CREATE {
					withdrawInDb.OrderId = sendOrder.OrderId
					withdrawInDb.Txid = txid
					withdrawInDb.Status = db.WITHDRAW_STATUS_INIT
					err = s.saveWithdraw(tx, withdrawInDb)
					if err != nil {
						return err
					}
				} else {
					return errors.New("withdraw status is not valid")
				}
			}
			for _, vout := range vouts {
				vout.ID = 0
				vout.OrderId = sendOrder.OrderId
				err = s.saveVout(tx, vout)
				if err != nil {
					return err
				}
			}
		}
		if order.Status == db.ORDER_STATUS_CONFIRMED || order.Status == db.ORDER_STATUS_PROCESSED || order.Status == db.ORDER_STATUS_CLOSED {
			return nil
		}
		order.Status = db.ORDER_STATUS_PENDING
		order.UpdatedAt = time.Now()
		order.ExternalTxId = externalTxId
		err = s.saveOrder(tx, order)
		if err != nil {
			return err
		}
		err = s.updateOtherStatusByOrder(tx, order.OrderId, db.ORDER_STATUS_PENDING, false)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

// UpdateSendOrderConfirmed
// when a withdrawal or consolidation request is confirmed, save to confirmed
func (s *State) UpdateSendOrderConfirmed(txid string, btcBlock uint64) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		order, err := s.getOrderByTxid(tx, txid)
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}

		// order found
		if order != nil && err == nil {
			if order.Status == db.ORDER_STATUS_CONFIRMED || order.Status == db.ORDER_STATUS_PROCESSED || order.Status == db.ORDER_STATUS_CLOSED {
				return nil
			}

			order.BtcBlock = btcBlock
			order.Status = db.ORDER_STATUS_CONFIRMED
			order.UpdatedAt = time.Now()
			err = s.saveOrder(tx, order)
			if err != nil {
				return err
			}
			err = s.updateOtherStatusByOrder(tx, order.OrderId, db.ORDER_STATUS_CONFIRMED, false)
			if err != nil {
				return err
			}
			vins, err := s.getVinsByOrderId(tx, order.OrderId)
			if err != nil {
				return err
			}
			for _, vin := range vins {
				// update utxo to spent
				err = s.updateUtxoStatusSpent(tx, vin.Txid, vin.OutIndex, order.BtcBlock)
				if err != nil {
					return err
				}
			}
			return nil
		}

		// order not found, update by txid, it happens in recovery model
		// should check withdraw[0] when layer2 fast than BTC, if withdraw exists and status processed, update other status to processed
		otherStatus := db.WITHDRAW_STATUS_CONFIRMED
		found, err := s.hasWithdrawByTxidAndStatus(tx, txid, db.WITHDRAW_STATUS_PROCESSED)
		if err != nil {
			return err
		}
		if found {
			otherStatus = db.WITHDRAW_STATUS_PROCESSED
		}
		err = s.updateOtherStatusByTxid(tx, txid, otherStatus)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

func (s *State) UpdateWithdrawInitialized(txid string, pid uint64) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		orders, err := s.getAllOrdersByTxid(tx, txid)
		if err != nil {
			return err
		}
		if len(orders) == 0 {
			return nil
		}

		// order found
		for i, order := range orders {
			// Skip if order is already in a finalized state (confirmed, processed)
			// But allow recovery from closed state
			if order.Status != db.ORDER_STATUS_AGGREGATING && order.Status != db.ORDER_STATUS_CLOSED {
				continue
			}

			// the latest one is init, others are closed
			if i == 0 {
				order.Status = db.ORDER_STATUS_INIT
			} else {
				order.Status = db.ORDER_STATUS_CLOSED
			}
			order.UpdatedAt = time.Now()
			order.Pid = pid
			err = s.saveOrder(tx, order)
			if err != nil {
				return err
			}
			// update vin, vout to order status
			err = s.updateOtherStatusByOrder(tx, order.OrderId, order.Status, true)
			if err != nil {
				return err
			}
			// update withdraw status to init, withdraw always not change if tx id is same
			err = s.updateWithdrawStatusByOrderId(tx, db.WITHDRAW_STATUS_INIT, order.OrderId, db.WITHDRAW_STATUS_CREATE, db.WITHDRAW_STATUS_AGGREGATING, db.WITHDRAW_STATUS_CLOSED)
			if err != nil {
				return err
			}
			if order.Status != db.ORDER_STATUS_INIT {
				continue
			}
			vins, err := s.getVinsByOrderId(tx, order.OrderId)
			if err != nil {
				return err
			}
			for _, vin := range vins {
				// update utxo to pending
				err = s.updateUtxoStatusPending(tx, vin.Txid, vin.OutIndex)
				if err != nil {
					return err
				}
			}
		}
		// order not found, do nothing
		return nil
	})
	return err
}

func (s *State) UpdateWithdrawFinalized(txid string, pid uint64) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		orders, err := s.getAllOrdersByTxid(tx, txid)
		if err != nil {
			return err
		}
		if len(orders) == 0 {
			return nil
		}

		// order found
		for _, order := range orders {
			// update withdraw status to processed, withdraw always not change if tx id is same
			err = s.updateWithdrawStatusByOrderId(tx, db.WITHDRAW_STATUS_PROCESSED, order.OrderId)
			if err != nil {
				return err
			}
			if order.Status != db.ORDER_STATUS_INIT && order.Status != db.ORDER_STATUS_PENDING && order.Status != db.ORDER_STATUS_CONFIRMED {
				continue
			}

			order.Status = db.ORDER_STATUS_PROCESSED
			order.Pid = pid
			order.UpdatedAt = time.Now()

			err = s.saveOrder(tx, order)
			if err != nil {
				return err
			}
			err = s.updateOtherStatusByOrder(tx, order.OrderId, db.ORDER_STATUS_PROCESSED, true)
			if err != nil {
				return err
			}
			vins, err := s.getVinsByOrderId(tx, order.OrderId)
			if err != nil {
				return err
			}
			for _, vin := range vins {
				// update utxo to spent
				err = s.updateUtxoStatusSpent(tx, vin.Txid, vin.OutIndex, order.BtcBlock)
				if err != nil {
					return err
				}
			}
		}

		// not found update by txid
		err = s.updateOtherStatusByTxid(tx, txid, db.ORDER_STATUS_PROCESSED)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

func (s *State) CleanProcessingWithdrawByOrderId(orderId string) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		order, err := s.getOrderByOrderId(tx, orderId)
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		if order == nil {
			return nil
		}
		if order.Status != db.ORDER_STATUS_AGGREGATING {
			return nil
		}
		order.Status = db.ORDER_STATUS_CLOSED
		order.UpdatedAt = time.Now()

		err = s.saveOrder(tx, order)
		if err != nil {
			return err
		}

		// update UTXO from pending to processed by vins
		vins, err := s.getVinsByOrderId(tx, order.OrderId)
		if err != nil {
			return err
		}
		for _, vin := range vins {
			var utxoInDb db.Utxo
			if err = tx.Where("txid = ? and out_index = ?", vin.Txid, vin.OutIndex).First(&utxoInDb).Error; err != nil {
				continue
			}
			if utxoInDb.Status != db.UTXO_STATUS_PENDING {
				continue
			}
			err = tx.Model(&db.Utxo{}).Where("id = ?", utxoInDb.ID).Updates(&db.Utxo{Status: db.UTXO_STATUS_PROCESSED, UpdatedAt: time.Now()}).Error
			if err != nil {
				log.Errorf("State CleanProcessingWithdraw update utxo txid %s - out %d error: %v", utxoInDb.Txid, utxoInDb.OutIndex, err)
				return err
			}
		}

		err = s.updateOtherStatusByOrder(tx, order.OrderId, db.ORDER_STATUS_CLOSED, true)
		if err != nil {
			return err
		}

		// restore withdraw from aggregating to create
		err = s.updateWithdrawStatusByOrderId(tx, db.WITHDRAW_STATUS_CREATE, order.OrderId, db.WITHDRAW_STATUS_AGGREGATING)
		if err != nil {
			return err
		}

		// restore safebox task from init to received_ok
		// Note: if on-chain event arrives later, UpdateSafeboxTaskInitOK will recover the order
		err = s.updateSafeboxTaskStatusByOrderId(tx, db.TASK_STATUS_RECEIVED_OK, order.OrderId, db.TASK_STATUS_INIT)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

// CleanProcessingWithdraw, clean all status "aggregating" orders and related withdraws
func (s *State) CleanProcessingWithdraw() error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		orders, err := s.getOrderByStatuses(tx, db.ORDER_STATUS_AGGREGATING)
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}

		// order found
		if len(orders) > 0 && err == nil {
			for _, order := range orders {
				if order.Status != db.ORDER_STATUS_AGGREGATING {
					continue
				}
				order.Status = db.ORDER_STATUS_CLOSED
				order.UpdatedAt = time.Now()

				err = s.saveOrder(tx, order)
				if err != nil {
					return err
				}

				// update UTXO from pending to processed by vins
				vins, err := s.getVinsByOrderId(tx, order.OrderId)
				if err != nil {
					return err
				}
				for _, vin := range vins {
					var utxoInDb db.Utxo
					if err = tx.Where("txid = ? and out_index = ?", vin.Txid, vin.OutIndex).First(&utxoInDb).Error; err != nil {
						continue
					}
					if utxoInDb.Status != db.UTXO_STATUS_PENDING {
						continue
					}
					err = tx.Model(&db.Utxo{}).Where("id = ?", utxoInDb.ID).Updates(&db.Utxo{Status: db.UTXO_STATUS_PROCESSED, UpdatedAt: time.Now()}).Error
					if err != nil {
						log.Errorf("State CleanProcessingWithdraw update utxo txid %s - out %d error: %v", utxoInDb.Txid, utxoInDb.OutIndex, err)
						return err
					}
				}

				err = s.updateOtherStatusByOrder(tx, order.OrderId, db.ORDER_STATUS_CLOSED, true)
				if err != nil {
					return err
				}

				// restore withdraw from aggregating to create
				err = s.updateWithdrawStatusByOrderId(tx, db.WITHDRAW_STATUS_CREATE, order.OrderId, db.WITHDRAW_STATUS_AGGREGATING)
				if err != nil {
					return err
				}

				// restore safebox task from init to received_ok
				// Note: if on-chain event arrives later, UpdateSafeboxTaskInitOK will recover the order
				err = s.updateSafeboxTaskStatusByOrderId(tx, db.TASK_STATUS_RECEIVED_OK, order.OrderId, db.TASK_STATUS_INIT)
				if err != nil {
					return err
				}
				return nil
			}
		}

		// not found order, do not delete withdraw, just update status to create
		err = s.updateWithdrawStatusByStatuses(tx, db.WITHDRAW_STATUS_CREATE, db.WITHDRAW_STATUS_AGGREGATING)
		if err != nil {
			return err
		}

		// not found order, do not delete vin/vout, just update status to closed
		err = s.updateOtherStatusByStatuses(tx, db.WITHDRAW_STATUS_CLOSED, db.WITHDRAW_STATUS_CREATE, db.WITHDRAW_STATUS_AGGREGATING)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

// UtxoSpentChecker is a callback function to check if a UTXO is spent on BTC chain
// Returns true if the UTXO is spent, false if it's still unspent
type UtxoSpentChecker func(txid string, outIndex int) (spent bool, err error)

// CleanInitializedNeedRbfWithdrawByOrderId cleans a specific order by orderId when UTXO conflict is detected
// It checks each UTXO's spent status via the callback:
// - If spent → mark as UTXO_STATUS_SPENT
// - If not spent → restore to UTXO_STATUS_PROCESSED
// For safebox orders: resets safebox_task to received_ok for re-aggregation
// For withdrawal orders: marks order as RBF_REQUEST for ReplaceWithdrawalV2 submission
// Returns the order type so caller can trigger appropriate follow-up action
func (s *State) CleanInitializedNeedRbfWithdrawByOrderId(orderId string, checkUtxoSpent UtxoSpentChecker) (orderType string, err error) {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err = s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		order, err := s.getOrderByOrderId(tx, orderId)
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		if order == nil {
			log.Warnf("CleanInitializedNeedRbfWithdrawByOrderId order not found: %s", orderId)
			return nil
		}
		if order.Status != db.ORDER_STATUS_INIT && order.Status != db.ORDER_STATUS_PENDING {
			log.Warnf("CleanInitializedNeedRbfWithdrawByOrderId order %s status is %s, not init/pending, skip", orderId, order.Status)
			return nil
		}

		orderType = order.OrderType
		log.Infof("CleanInitializedNeedRbfWithdrawByOrderId processing order: %s, type: %s", order.OrderId, orderType)

		// Check each UTXO's spent status and update accordingly
		vins, err := s.getVinsByOrderId(tx, order.OrderId)
		if err != nil {
			return err
		}

		for _, vin := range vins {
			var utxoInDb db.Utxo
			if err = tx.Where("txid = ? and out_index = ?", vin.Txid, vin.OutIndex).First(&utxoInDb).Error; err != nil {
				log.Warnf("CleanInitializedNeedRbfWithdrawByOrderId UTXO %s:%d not found in db, skip", vin.Txid, vin.OutIndex)
				continue
			}
			// Skip UTXOs already marked as spent
			if utxoInDb.Status == db.UTXO_STATUS_SPENT {
				continue
			}

			// Check if UTXO is spent on BTC chain
			spent, checkErr := checkUtxoSpent(vin.Txid, int(vin.OutIndex))
			if checkErr != nil {
				log.Warnf("CleanInitializedNeedRbfWithdrawByOrderId failed to check UTXO %s:%d spent status: %v", vin.Txid, vin.OutIndex, checkErr)
				continue
			}

			if spent {
				// UTXO is spent on chain, mark as spent
				log.Infof("CleanInitializedNeedRbfWithdrawByOrderId UTXO %s:%d is spent, marking as spent", vin.Txid, vin.OutIndex)
				err = tx.Model(&db.Utxo{}).Where("id = ?", utxoInDb.ID).Updates(&db.Utxo{
					Status:    db.UTXO_STATUS_SPENT,
					UpdatedAt: time.Now(),
				}).Error
			} else {
				// UTXO is not spent, restore to processed
				log.Infof("CleanInitializedNeedRbfWithdrawByOrderId UTXO %s:%d is not spent, restoring to processed", vin.Txid, vin.OutIndex)
				err = tx.Model(&db.Utxo{}).Where("id = ?", utxoInDb.ID).Updates(&db.Utxo{
					Status:    db.UTXO_STATUS_PROCESSED,
					UpdatedAt: time.Now(),
				}).Error
			}
			if err != nil {
				log.Errorf("CleanInitializedNeedRbfWithdrawByOrderId update utxo txid %s - out %d error: %v", utxoInDb.Txid, utxoInDb.OutIndex, err)
				return err
			}
		}

		// Handle differently based on order type
		if orderType == db.ORDER_TYPE_SAFEBOX {
			// For safebox: close order and reset task for re-aggregation
			order.Status = db.ORDER_STATUS_CLOSED
			order.UpdatedAt = time.Now()
			err = s.saveOrder(tx, order)
			if err != nil {
				return err
			}

			// Update vin/vout status to closed
			err = s.updateOtherStatusByOrder(tx, order.OrderId, db.ORDER_STATUS_CLOSED, true)
			if err != nil {
				return err
			}

			// Reset safebox task from init/init_ok to received_ok for re-aggregation
			err = s.updateSafeboxTaskStatusByOrderId(tx, db.TASK_STATUS_RECEIVED_OK, order.OrderId, db.TASK_STATUS_INIT, db.TASK_STATUS_INIT_OK)
			if err != nil {
				return err
			}
			log.Infof("CleanInitializedNeedRbfWithdrawByOrderId safebox order %s: closed, task reset to received_ok", order.OrderId)
		} else if orderType == db.ORDER_TYPE_WITHDRAWAL {
			// For withdrawal: mark order as RBF_REQUEST for ReplaceWithdrawalV2
			// The order keeps its Pid so ReplaceWithdrawalV2 can reference it
			order.Status = db.ORDER_STATUS_RBF_REQUEST
			order.UpdatedAt = time.Now()
			err = s.saveOrder(tx, order)
			if err != nil {
				return err
			}

			// Update vin/vout status to closed (old vins are no longer valid)
			err = s.updateOtherStatusByOrder(tx, order.OrderId, db.ORDER_STATUS_CLOSED, true)
			if err != nil {
				return err
			}

			// Restore withdraws to aggregating status so they can be re-processed
			err = s.updateWithdrawStatusByOrderId(tx, db.WITHDRAW_STATUS_AGGREGATING, order.OrderId, db.WITHDRAW_STATUS_PENDING)
			if err != nil {
				return err
			}
			log.Infof("CleanInitializedNeedRbfWithdrawByOrderId withdrawal order %s: marked as RBF_REQUEST, Pid: %d", order.OrderId, order.Pid)
		} else {
			// For consolidation or other types: just close
			order.Status = db.ORDER_STATUS_CLOSED
			order.UpdatedAt = time.Now()
			err = s.saveOrder(tx, order)
			if err != nil {
				return err
			}
			err = s.updateOtherStatusByOrder(tx, order.OrderId, db.ORDER_STATUS_CLOSED, true)
			if err != nil {
				return err
			}
			log.Infof("CleanInitializedNeedRbfWithdrawByOrderId order %s type %s: closed", order.OrderId, orderType)
		}

		return nil
	})
	return orderType, err
}

func (s *State) GetWithdrawsCanStart() ([]*db.Withdraw, error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	withdraws, err := s.getWithdrawByStatuses(nil, "tx_price desc", db.WITHDRAW_STATUS_CREATE)
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return nil, err
		}
		return nil, nil
	}

	return withdraws, nil
}

func (s *State) GetWithdrawsCanceling() ([]*db.Withdraw, error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	withdraws, err := s.getWithdrawByStatuses(nil, "id asc", db.WITHDRAW_STATUS_CANCELING)
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return nil, err
		}
		return nil, nil
	}
	return withdraws, nil
}

func (s *State) GetWithdrawsByOrderId(orderId string) ([]*db.Withdraw, error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	var withdraws []*db.Withdraw
	result := s.dbm.GetWalletDB().Where("order_id = ?", orderId).Order("id asc").Find(&withdraws)
	if result.Error != nil {
		return nil, result.Error
	}

	return withdraws, nil
}

func (s *State) GetSendOrderInitlized() ([]*db.SendOrder, error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	sendOrders, err := s.getOrderByStatuses(nil, "tx_price desc", db.ORDER_STATUS_INIT)
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return nil, err
		}
		return nil, nil
	}

	return sendOrders, nil
}

func (s *State) GetSendOrderPending(limit int) ([]*db.SendOrder, error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	var pendingOrders []*db.SendOrder
	err := s.dbm.GetWalletDB().Where("status = ?", db.ORDER_STATUS_PENDING).Order("id asc").Limit(limit).Find(&pendingOrders).Error
	if err != nil {
		return nil, err
	}

	return pendingOrders, nil
}

// GetSendOrderByTxIdOrExternalId get send order by txid or external id
func (s *State) GetSendOrderByTxIdOrExternalId(id string) (*db.SendOrder, error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	sendOrder, err := s.getOrderByTxid(nil, id)
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	if err == gorm.ErrRecordNotFound {
		sendOrder, err = s.getOrderByExternalId(nil, id)
		if err != nil && err != gorm.ErrRecordNotFound {
			return nil, err
		}
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
	}
	return sendOrder, nil
}

// GetSendOrdersNeedRbf returns orders with RBF_REQUEST status that need to be re-submitted
// via ReplaceWithdrawalV2
func (s *State) GetSendOrdersNeedRbf() ([]*db.SendOrder, error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	var orders []*db.SendOrder
	err := s.dbm.GetWalletDB().Where("status = ? AND order_type = ?",
		db.ORDER_STATUS_RBF_REQUEST, db.ORDER_TYPE_WITHDRAWAL).
		Order("id asc").Find(&orders).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	return orders, nil
}

// GetSendOrderByOrderId returns a send order by its orderId
func (s *State) GetSendOrderByOrderId(orderId string) (*db.SendOrder, error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	return s.getOrderByOrderId(nil, orderId)
}

// CreateRbfSendOrder creates a new RBF send order, closes the original order, and updates UTXO statuses
func (s *State) CreateRbfSendOrder(newOrder *db.SendOrder, originalOrderId string, selectedUtxos []*db.Utxo, vins []*db.Vin, vouts []*db.Vout) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		// Close the original order
		err := tx.Model(&db.SendOrder{}).Where("order_id = ?", originalOrderId).Updates(&db.SendOrder{
			Status:    db.ORDER_STATUS_CLOSED,
			UpdatedAt: time.Now(),
		}).Error
		if err != nil {
			return fmt.Errorf("failed to close original order: %v", err)
		}

		// Save new order
		err = s.saveOrder(tx, newOrder)
		if err != nil {
			return err
		}

		// Save vins
		if err = tx.Create(&vins).Error; err != nil {
			return err
		}

		// Save vouts
		if err = tx.Create(&vouts).Error; err != nil {
			return err
		}

		// Update UTXO statuses to pending
		for _, utxo := range selectedUtxos {
			var utxoInDb db.Utxo
			if err = tx.Where("txid = ? and out_index = ?", utxo.Txid, utxo.OutIndex).Order("id desc").First(&utxoInDb).Error; err != nil {
				return err
			}
			// Only update if UTXO is in confirmed status
			if utxoInDb.Status == db.UTXO_STATUS_CONFIRMED {
				err = tx.Model(&db.Utxo{}).Where("id = ?", utxoInDb.ID).Updates(&db.Utxo{
					Status:    db.UTXO_STATUS_PENDING,
					UpdatedAt: time.Now(),
				}).Error
				if err != nil {
					return err
				}
			}
		}

		// Update withdrawals to reference new order
		err = tx.Model(&db.Withdraw{}).Where("order_id = ?", originalOrderId).Updates(&db.Withdraw{
			OrderId:   newOrder.OrderId,
			Txid:      newOrder.Txid,
			Status:    db.WITHDRAW_STATUS_AGGREGATING,
			UpdatedAt: time.Now(),
		}).Error
		if err != nil {
			return fmt.Errorf("failed to update withdrawals for RBF: %v", err)
		}

		return nil
	})

	return err
}

// GetLatestWithdrawSendOrderConfirmed get latest confirmed withdraw send order
func (s *State) GetLatestWithdrawSendOrderConfirmed() (*db.SendOrder, error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	var sendOrder *db.SendOrder
	err := s.dbm.GetWalletDB().Where("status = ? and order_type = ?", db.ORDER_STATUS_CONFIRMED, db.ORDER_TYPE_WITHDRAWAL).First(&sendOrder).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	log.Debugf("GetSendOrderConfirmed sendOrder found: %v", sendOrder.Txid)
	return sendOrder, nil
}

func (s *State) CloseWithdrawByRequestId(requestId uint64, reason string) error {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	err := s.dbm.GetWalletDB().Model(&db.Withdraw{}).Where("request_id = ?", requestId).Updates(&db.Withdraw{Status: db.WITHDRAW_STATUS_CLOSED, Reason: reason, UpdatedAt: time.Now()}).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		log.Errorf("State CloseWithdraw Withdraw by request id: %d, reason: %s, error: %v", requestId, reason, err)
		return err
	}
	return nil
}

func (s *State) getWithdraw(evmTxId string) (*db.Withdraw, error) {
	var withdraw db.Withdraw
	result := s.dbm.GetWalletDB().Where("evm_tx_id=?", evmTxId).Order("id desc").First(&withdraw)
	if result.Error != nil {
		return nil, result.Error
	}
	return &withdraw, nil
}

func (s *State) getSendOrder(orderId string) (*db.SendOrder, error) {
	var order db.SendOrder
	result := s.dbm.GetWalletDB().Where("order_id=?", orderId).Order("id desc").First(&order)
	if result.Error != nil {
		return nil, result.Error
	}
	return &order, nil
}

func (s *State) getSendOrderByPid(pid uint64) (*db.SendOrder, error) {
	var order db.SendOrder
	result := s.dbm.GetWalletDB().Where("pid = ?", pid).Order("id desc").First(&order)
	if result.Error != nil {
		return nil, result.Error
	}
	return &order, nil
}

// queryWithdrawByEvmTxId
func (s *State) getWithdrawByRequestId(tx *gorm.DB, requestId uint64) (*db.Withdraw, error) {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	var withdraw db.Withdraw
	result := tx.Where("request_id=?", requestId).First(&withdraw)
	if result.Error != nil {
		return nil, result.Error
	}
	return &withdraw, nil
}

func (s *State) hasWithdrawByTxidAndStatus(tx *gorm.DB, txid string, status string) (bool, error) {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	var withdraw db.Withdraw
	err := tx.Where("txid=? and status=?", txid, status).First(&withdraw).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return false, err
	}
	if err == gorm.ErrRecordNotFound {
		return false, nil
	}
	return true, nil
}

func (s *State) getAllOrdersByTxid(tx *gorm.DB, txid string) ([]*db.SendOrder, error) {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	var orders []*db.SendOrder
	err := tx.Where("txid=?", txid).Order("id DESC").Find(&orders).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return orders, nil
}

func (s *State) getOrderByTxid(tx *gorm.DB, txid string) (*db.SendOrder, error) {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	var order db.SendOrder
	result := tx.Where("txid=?", txid).Order("id DESC").First(&order)
	if result.Error != nil {
		return nil, result.Error
	}
	return &order, nil
}

func (s *State) getOrderByExternalId(tx *gorm.DB, externalId string) (*db.SendOrder, error) {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	var order db.SendOrder
	result := tx.Where("external_tx_id=?", externalId).Order("id DESC").First(&order)
	if result.Error != nil {
		return nil, result.Error
	}
	return &order, nil
}

func (s *State) getOrderByTxidAndStatuses(tx *gorm.DB, txid string, statuses ...string) (*db.SendOrder, error) {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	var order db.SendOrder
	result := tx.Where("txid=? and status in (?)", txid, statuses).Order("id DESC").First(&order)
	if result.Error != nil {
		return nil, result.Error
	}
	return &order, nil
}

func (s *State) getOrderByOrderId(tx *gorm.DB, orderId string) (*db.SendOrder, error) {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	var order db.SendOrder
	result := tx.Where("order_id=?", orderId).First(&order)
	if result.Error != nil {
		return nil, result.Error
	}
	return &order, nil
}

func (s *State) getOrderByStatuses(tx *gorm.DB, statuses ...string) ([]*db.SendOrder, error) {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	var orders []*db.SendOrder
	result := tx.Where("status in (?)", statuses).Find(&orders)
	if result.Error != nil {
		return nil, result.Error
	}
	return orders, nil
}

func (s *State) getWithdrawByStatuses(tx *gorm.DB, orderBy string, statuses ...string) ([]*db.Withdraw, error) {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	if orderBy == "" {
		orderBy = "id asc"
	}
	var withdraws []*db.Withdraw
	result := tx.Where("status in (?)", statuses).Order(orderBy).Find(&withdraws)
	if result.Error != nil {
		return nil, result.Error
	}
	return withdraws, nil
}

func (s *State) saveWithdraw(tx *gorm.DB, withdraw *db.Withdraw) error {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	result := tx.Save(withdraw)
	if result.Error != nil {
		log.Errorf("State saveWithdraw error: %v", result.Error)
		return result.Error
	}
	return nil
}

func (s *State) saveOrder(tx *gorm.DB, order *db.SendOrder) error {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	result := tx.Save(order)
	if result.Error != nil {
		log.Errorf("State saveOrder error: %v", result.Error)
		return result.Error
	}
	return nil
}

func (s *State) updateOtherStatusByOrder(tx *gorm.DB, orderId string, status string, excludeWithdraw bool) error {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	var err error
	if !excludeWithdraw {
		err = tx.Model(&db.Withdraw{}).Where("order_id = ?", orderId).Updates(&db.Withdraw{Status: status, UpdatedAt: time.Now()}).Error
		if err != nil {
			log.Errorf("State updateOtherStatusByOrder Withdraw by order id: %s, status: %s, error: %v", orderId, status, err)
			return err
		}
		err = tx.Model(&db.SafeboxTask{}).Where("order_id = ?", orderId).Updates(&db.SafeboxTask{Status: status, UpdatedAt: time.Now()}).Error
		if err != nil {
			log.Errorf("State updateOtherStatusByOrder Safebox Task by order id: %s, status: %s, error: %v", orderId, status, err)
			return err
		}
	}
	err = tx.Model(&db.Vin{}).Where("order_id = ?", orderId).Updates(&db.Vin{Status: status, UpdatedAt: time.Now()}).Error
	if err != nil {
		log.Errorf("State updateOtherStatusByOrder Vin by order id: %s, status: %s, error: %v", orderId, status, err)
		return err
	}
	err = tx.Model(&db.Vout{}).Where("order_id = ?", orderId).Updates(&db.Vout{Status: status, UpdatedAt: time.Now()}).Error
	if err != nil {
		log.Errorf("State updateOtherStatusByOrder Vout by order id: %s, status: %s, error: %v", orderId, status, err)
		return err
	}
	return nil
}

func (s *State) updateWithdrawStatusByStatuses(tx *gorm.DB, newStatus string, rawStatuses ...string) error {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	err := tx.Model(&db.Withdraw{}).Where("status in (?)", rawStatuses).Updates(&db.Withdraw{Status: newStatus, UpdatedAt: time.Now()}).Error
	if err != nil {
		log.Errorf("State updateWithdrawStatusByStatuses Withdraw by raw status: %v, new status: %s, error: %v", rawStatuses, newStatus, err)
		return err
	}
	return nil
}

func (s *State) updateSafeboxTaskStatusByOrderId(tx *gorm.DB, status string, orderId string, rawStatuses ...string) error {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	var err error
	if len(rawStatuses) == 0 {
		err = tx.Model(&db.SafeboxTask{}).Where("order_id = ?", orderId).Updates(&db.SafeboxTask{Status: status, UpdatedAt: time.Now()}).Error
	} else {
		err = tx.Model(&db.SafeboxTask{}).Where("order_id = ? and status in (?)", orderId, rawStatuses).Updates(&db.SafeboxTask{Status: status, UpdatedAt: time.Now()}).Error
	}
	if err != nil {
		log.Errorf("State updateSafeboxTaskStatusByOrderId SafeboxTask by order id: %s, status: %s, error: %v", orderId, status, err)
		return err
	}
	return nil
}

func (s *State) updateWithdrawStatusByOrderId(tx *gorm.DB, status string, orderId string, rawStatuses ...string) error {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	var err error
	if len(rawStatuses) == 0 {
		err = tx.Model(&db.Withdraw{}).Where("order_id = ?", orderId).Updates(&db.Withdraw{Status: status, UpdatedAt: time.Now()}).Error
	} else {
		err = tx.Model(&db.Withdraw{}).Where("order_id = ? and status in (?)", orderId, rawStatuses).Updates(&db.Withdraw{Status: status, UpdatedAt: time.Now()}).Error
	}
	if err != nil {
		log.Errorf("State updateOtherStatusByOrder Withdraw by order id: %s, status: %s, error: %v", orderId, status, err)
		return err
	}
	return nil
}

func (s *State) updateOtherStatusByStatuses(tx *gorm.DB, newStatus string, rawStatuses ...string) error {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	err := tx.Model(&db.Vin{}).Where("status in (?)", rawStatuses).Updates(&db.Vin{Status: newStatus, UpdatedAt: time.Now()}).Error
	if err != nil {
		log.Errorf("State updateOtherStatusByStatuses Vin by raw statuses: %v, new status: %s, error: %v", rawStatuses, newStatus, err)
		return err
	}
	err = tx.Model(&db.Vout{}).Where("status in (?)", rawStatuses).Updates(&db.Vout{Status: newStatus, UpdatedAt: time.Now()}).Error
	if err != nil {
		log.Errorf("State updateOtherStatusByStatuses Vout by raw statuses: %v, new status: %s, error: %v", rawStatuses, newStatus, err)
		return err
	}
	return nil
}

// updateOtherStatusByTxid will update other status by txid, it is used in recovery model that can not restore send order
func (s *State) updateOtherStatusByTxid(tx *gorm.DB, txid string, status string) error {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	err := tx.Model(&db.Withdraw{}).Where("txid = ?", txid).Updates(&db.Withdraw{Status: status, UpdatedAt: time.Now()}).Error
	if err != nil {
		log.Errorf("State updateOtherStatusByTxid Withdraw by order id: %s, status: %s, error: %v", txid, status, err)
		return err
	}
	err = tx.Model(&db.SafeboxTask{}).Where("timelock_txid = ?", txid).Updates(&db.SafeboxTask{Status: status, UpdatedAt: time.Now()}).Error
	if err != nil {
		log.Errorf("State updateOtherStatusByTxid Withdraw by order id: %s, status: %s, error: %v", txid, status, err)
		return err
	}
	err = tx.Model(&db.Vin{}).Where("txid = ?", txid).Updates(&db.Vin{Status: status, UpdatedAt: time.Now()}).Error
	if err != nil {
		log.Errorf("State updateOtherStatusByTxid Vin by order id: %s, status: %s, error: %v", txid, status, err)
		return err
	}
	err = tx.Model(&db.Vout{}).Where("txid = ?", txid).Updates(&db.Vout{Status: status, UpdatedAt: time.Now()}).Error
	if err != nil {
		log.Errorf("State updateOtherStatusByTxid Vout by order id: %s, status: %s, error: %v", txid, status, err)
		return err
	}
	return nil
}
