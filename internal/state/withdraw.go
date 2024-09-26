package state

import (
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// CreateWithdrawal
// when a new withdrawal request is detected, save to unconfirmed
func (s *State) CreateWithdrawal(address string, block, id, maxTxFee, amount uint64) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	// check if exist, if not save to db
	_, err := s.getWithdrawByRequestId(id)
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
		From:      "",
		To:        address,
		Amount:    amount,
		MaxTxFee:  maxTxFee,
		Status:    "create",
		OrderId:   "",
		UpdatedAt: time.Now(),
	}

	return s.saveWithdraw(withdraw)
}

func (s *State) UpdateWithdrawReplace(id, txPrice uint64) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	withdraw, err := s.getWithdrawByRequestId(id)
	if err != nil {
		return err
	}
	if withdraw.Status != "create" && withdraw.Status != "aggregating" {
		// ignore if it is not create status
		// it is hard to update after start withdraw sig program
		return nil
	}

	withdraw.MaxTxFee = txPrice
	withdraw.UpdatedAt = time.Now()

	// TODO notify stop aggregating if it is aggregating status, set to closed

	return s.saveWithdraw(withdraw)
}

func (s *State) UpdateWithdrawCancel(id uint64) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	withdraw, err := s.getWithdrawByRequestId(id)
	if err != nil {
		return err
	}
	if withdraw.Status != "create" && withdraw.Status != "aggregating" {
		// ignore if it is not create status
		// it is hard to update after start withdraw sig program
		return nil
	}

	withdraw.Status = "closed"
	withdraw.UpdatedAt = time.Now()

	// TODO notify stop aggregating if it is aggregating status, set to closed

	return s.saveWithdraw(withdraw)
}

// SaveConfirmWithdraw
// when a withdrawal request is confirmed, save to confirmed
func (s *State) SaveConfirmWithdraw(txid string) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	withdraw, err := s.getOrderByTxid(nil, txid)
	if err != nil {
		return err
	}

	withdraw.Status = "confirmed"
	withdraw.UpdatedAt = time.Now()

	result := s.dbm.GetWalletDB().Save(withdraw)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (s *State) UpdateWithdrawInitialized(txid string) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		order, err := s.getOrderByTxid(tx, txid)
		if err != nil {
			return err
		}

		if order.Status != "aggregating" {
			return nil
		}

		order.Status = "init"
		order.UpdatedAt = time.Now()

		err = s.saveOrder(tx, order)
		if err != nil {
			return err
		}
		err = s.updateOtherStatusByOrder(tx, order.OrderId, "init")
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

func (s *State) UpdateWithdrawFinalized(txid string) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		order, err := s.getOrderByTxid(tx, txid)
		if err != nil {
			return err
		}

		if order.Status == "processed" {
			return nil
		}

		order.Status = "processed"
		order.UpdatedAt = time.Now()

		err = s.saveOrder(tx, order)
		if err != nil {
			return err
		}
		err = s.updateOtherStatusByOrder(tx, order.OrderId, "processed")
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

// queryWithdrawByEvmTxId
func (s *State) getWithdrawByRequestId(requestId uint64) (*db.Withdraw, error) {
	var withdraw db.Withdraw
	result := s.dbm.GetWalletDB().Where("request_id=?", requestId).First(&withdraw)
	if result.Error != nil {
		return nil, result.Error
	}
	return &withdraw, nil
}

func (s *State) saveWithdraw(withdraw *db.Withdraw) error {
	result := s.dbm.GetWalletDB().Save(withdraw)
	if result.Error != nil {
		log.Errorf("State saveWithdraw error: %v", result.Error)
		return result.Error
	}
	return nil
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

func (s *State) updateOtherStatusByOrder(tx *gorm.DB, orderId string, status string) error {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	err := tx.Model(&db.Withdraw{}).Where("OrderId = ?", orderId).Updates(&db.Withdraw{Status: status, UpdatedAt: time.Now()}).Error
	if err != nil {
		log.Errorf("State updateOtherStatusByOrder Withdraw by order id: %s, status: %s, error: %v", orderId, status, err)
		return err
	}
	err = tx.Model(&db.Vin{}).Where("OrderId = ?", orderId).Updates(&db.Vin{Status: status, UpdatedAt: time.Now()}).Error
	if err != nil {
		log.Errorf("State updateOtherStatusByOrder Vin by order id: %s, status: %s, error: %v", orderId, status, err)
		return err
	}
	err = tx.Model(&db.Vout{}).Where("OrderId = ?", orderId).Updates(&db.Vout{Status: status, UpdatedAt: time.Now()}).Error
	if err != nil {
		log.Errorf("State updateOtherStatusByOrder Vout by order id: %s, status: %s, error: %v", orderId, status, err)
		return err
	}
	return nil
}
