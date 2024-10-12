package state

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/types"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func (s *State) UpdateUtxoStatusProcessed(txid string, out int) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	utxo, err := s.getUtxo(txid, out)
	if err != nil {
		return err
	}

	if utxo.Status == db.UTXO_STATUS_PENDING || utxo.Status == db.UTXO_STATUS_SPENT {
		return fmt.Errorf("wallet state UpdateUtxoStatusProcessed failed, utxo %s:%d, status %s", txid, out, utxo.Status)
	}
	if utxo.Status == db.UTXO_STATUS_PROCESSED {
		return nil
	}
	utxo.Status = db.UTXO_STATUS_PROCESSED
	return s.saveUtxo(utxo)
}

func (s *State) UpdateUtxoStatusSpent(txid string, out int, btcBlock uint64) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	return s.updateUtxoStatusSpent(txid, out, btcBlock)
}

func (s *State) AddUtxo(utxo *db.Utxo, pk []byte, blockHash string, blockHeight uint64, noWitnessTx []byte, merkleRoot []byte, proofBytes []byte, txIndex int) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	utxoExists, err := s.getUtxo(utxo.Txid, utxo.OutIndex)
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}
	if err == nil {
		// update
		utxo.ID = utxoExists.ID
		utxo.Status = utxoExists.Status
	}

	if utxo.Status == db.UTXO_STATUS_CONFIRMED {
		// check deposit table (from layer2)
		var depositResult db.DepositResult
		err := s.dbm.GetWalletDB().Where("txid=? and tx_out=?", utxo.Txid, utxo.OutIndex).First(&depositResult).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}

		// if found
		if err == nil {
			utxo.Source = db.UTXO_SOURCE_DEPOSIT
			utxo.Status = db.UTXO_STATUS_PROCESSED

			// recover sub script for p2wsh
			if len(utxo.SubScript) == 0 && utxo.ReceiverType == db.WALLET_TYPE_P2WSH {
				subScript, err := types.BuildSubScriptForP2WSH(depositResult.Address, pk)
				if err != nil {
					return err
				}
				utxo.SubScript = subScript
			}
		} else if len(noWitnessTx) > 0 {
			// check deposit cache table, if it not exist, save deposit cache table
			err = s.SaveConfirmDeposit(utxo.Txid, hex.EncodeToString(noWitnessTx), utxo.EvmAddr, 1, utxo.OutIndex, blockHash, blockHeight, merkleRoot, proofBytes, txIndex)
			if err != nil {
				log.Errorf("State AddUtxo SaveConfirmDeposit error: %v", err)
			}
		}
	}

	return s.saveUtxo(utxo)
}

func (s *State) UpdateUtxoSubScript(txid string, out uint64, evmAddr string, pk []byte) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	subScript, err := types.BuildSubScriptForP2WSH(evmAddr, pk)
	if err != nil {
		return err
	}

	err = s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		err := tx.Model(&db.Utxo{}).Where("txid=? and tx_out=?", txid, out).Update("sub_script", subScript).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		err = tx.Model(&db.DepositResult{}).Where("txid=? and tx_out=?", txid, out).Update("need_fetch_sub_script", false).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		return nil
	})
	return err
}

// GetDepositResultsNeedFetchSubScript get deposit results need fetch sub script, batch size is 100
func (s *State) GetDepositResultsNeedFetchSubScript() ([]*db.DepositResult, error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	var depositResults []*db.DepositResult
	err := s.dbm.GetWalletDB().Where("need_fetch_sub_script=? ", true).Limit(100).First(&depositResults).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	return depositResults, nil
}

func (s *State) AddDepositResult(txid string, out uint64, address string, amount uint64, blockHash string) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	utxo, err := s.getUtxo(txid, int(out))
	var needFetchSubScript bool
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}
	if err == nil && utxo.ReceiverType == db.WALLET_TYPE_P2WSH && len(utxo.SubScript) == 0 {
		needFetchSubScript = true
	}
	if err == nil && (utxo.Status == db.UTXO_STATUS_CONFIRMED || utxo.Status == db.UTXO_STATUS_UNCONFIRM) {
		utxo.Status = db.UTXO_STATUS_PROCESSED
		utxo.UpdatedAt = time.Now()
		err = s.saveUtxo(utxo)
		if err != nil {
			return err
		}
	}

	var depositResult db.DepositResult
	err = s.dbm.GetWalletDB().Where("txid=? and tx_out=?", txid, out).First(&depositResult).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}
	if err == nil {
		if depositResult.NeedFetchSubScript != needFetchSubScript {
			depositResult.NeedFetchSubScript = needFetchSubScript
			err = s.dbm.GetWalletDB().Save(&depositResult).Error
			if err != nil {
				return err
			}
		}
		return nil
	}

	err = s.dbm.GetWalletDB().Create(&db.DepositResult{
		Txid:               txid,
		TxOut:              out,
		Address:            address,
		Amount:             amount,
		BlockHash:          blockHash,
		NeedFetchSubScript: needFetchSubScript,
	}).Error

	return err
}

func (s *State) AddOrUpdateVin(vin *db.Vin) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	// 1. update utxo status spent
	err := s.updateUtxoStatusSpent(vin.Txid, vin.OutIndex, vin.BtcHeight)
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}

	// 2. check exist vin status
	// 2.1 if exists, update withdraw table and send order table
	vinExists, err := s.getVin(vin.Txid, vin.OutIndex)
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}
	// if vinExists is closed, add a new vin
	if vinExists != nil && vinExists.Status != db.ORDER_STATUS_CLOSED {
		if vinExists.Status == db.ORDER_STATUS_CONFIRMED || vinExists.Status == db.ORDER_STATUS_PROCESSED {
			return nil
		}
		vin.ID = vinExists.ID
		vin.UpdatedAt = time.Now()
		vin.OrderId = vinExists.OrderId
	}

	// 3. save vin
	return s.saveVin(vin)
}

func (s *State) AddOrUpdateVout(vout *db.Vout) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	// 1. check exist vout status
	// 1.1 if exists, update withdraw table and send order table
	voutExists, err := s.getVout(vout.Txid, vout.OutIndex)
	if err != nil && err != gorm.ErrRecordNotFound {
		return err
	}
	if voutExists != nil {
		if voutExists.Status == db.UTXO_STATUS_CONFIRMED || voutExists.Status == db.UTXO_STATUS_PROCESSED {
			return nil
		}
		vout.ID = voutExists.ID
		vout.UpdatedAt = time.Now()
		vout.OrderId = voutExists.OrderId
		vout.WithdrawId = voutExists.WithdrawId

		if vout.WithdrawId != "" {
			// TODO when found event from layer2, check vout with withdraw id
			// update withdraw table
			withdraw, err := s.getWithdraw(vout.WithdrawId)
			if err != nil && err != gorm.ErrRecordNotFound {
				return err
			}
			withdraw.Status = vout.Status
			withdraw.UpdatedAt = time.Now()
			err = s.dbm.GetWalletDB().Save(withdraw).Error
			if err != nil {
				return err
			}
		}

		if vout.OrderId != "" {
			// TODO when found event from layer2, check vout[0] with order id
			// update send order table
			order, err := s.getSendOrder(vout.OrderId)
			if err != nil && err != gorm.ErrRecordNotFound {
				return err
			}
			order.Status = vout.Status
			order.UpdatedAt = time.Now()
			order.BtcBlock = vout.BtcHeight
			err = s.dbm.GetWalletDB().Save(order).Error
			if err != nil {
				return err
			}
		}
	}

	// 2. save vout
	return s.saveVout(vout)
}

func (s *State) GetUtxoByOrderId(orderId string) (vinUtxos []*db.Utxo, err error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	vins, err := s.getVinsByOrderId(nil, orderId)
	if err != nil {
		return nil, err
	}
	for _, vin := range vins {
		var utxos []*db.Utxo
		err = s.dbm.GetWalletDB().Where("txid = ? and out_index = ?", vin.Txid, vin.OutIndex).Find(&utxos).Error
		if err != nil {
			return nil, err
		}
		vinUtxos = append(vinUtxos, utxos...)
	}

	return vinUtxos, nil
}

func (s *State) GetUtxoCanSpend() ([]*db.Utxo, error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	utxos, err := s.getUtxoByStatuses(nil, "amount desc", db.UTXO_STATUS_CONFIRMED, db.UTXO_STATUS_PROCESSED)
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return nil, err
		}
		return nil, nil
	}

	return utxos, nil
}

func (s *State) getVin(txid string, out int) (*db.Vin, error) {
	var vin db.Vin
	result := s.dbm.GetWalletDB().Where("txid=? and out_index=?", txid, out).Order("id desc").First(&vin)
	if result.Error != nil {
		return nil, result.Error
	}
	return &vin, nil
}

func (s *State) getVinsByOrderId(tx *gorm.DB, orderId string) ([]*db.Vin, error) {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	var vins []*db.Vin
	err := tx.Where("order_id=?", orderId).Find(&vins).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	return vins, nil
}

func (s *State) getVout(txid string, out int) (*db.Vout, error) {
	var vout db.Vout
	result := s.dbm.GetWalletDB().Where("txid=? and out_index=?", txid, out).Order("id desc").First(&vout)
	if result.Error != nil {
		return nil, result.Error
	}
	return &vout, nil
}

func (s *State) getUtxo(txid string, out int) (*db.Utxo, error) {
	var utxo db.Utxo
	result := s.dbm.GetWalletDB().Where("txid=? and out_index=?", txid, out).Order("id desc").First(&utxo)
	if result.Error != nil {
		return nil, result.Error
	}
	return &utxo, nil
}

func (s *State) getUtxoByStatuses(tx *gorm.DB, orderBy string, statuses ...string) ([]*db.Utxo, error) {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	if orderBy == "" {
		orderBy = "id asc"
	}
	var utxos []*db.Utxo
	result := tx.Where("status in (?)", statuses).Order(orderBy).Find(&utxos)
	if result.Error != nil {
		return nil, result.Error
	}
	return utxos, nil
}

func (s *State) saveUtxo(utxo *db.Utxo) error {
	result := s.dbm.GetWalletDB().Save(utxo)
	if result.Error != nil {
		log.Errorf("State saveUTXO error: %v", result.Error)
		return result.Error
	}
	s.walletState.Utxo = utxo
	return nil
}

func (s *State) saveVin(vin *db.Vin) error {
	result := s.dbm.GetWalletDB().Save(vin)
	if result.Error != nil {
		log.Errorf("State saveVin error: %v", result.Error)
		return result.Error
	}
	return nil
}

func (s *State) saveVout(vout *db.Vout) error {
	result := s.dbm.GetWalletDB().Save(vout)
	if result.Error != nil {
		log.Errorf("State saveVout error: %v", result.Error)
		return result.Error
	}
	return nil
}

func (s *State) updateUtxoStatusSpent(txid string, out int, btcBlock uint64) error {
	utxo, err := s.getUtxo(txid, out)
	if err != nil {
		return err
	}
	if utxo.Status == db.UTXO_STATUS_SPENT {
		return nil
	}

	utxo.Status = db.UTXO_STATUS_SPENT
	utxo.SpentBlock = btcBlock
	utxo.UpdatedAt = time.Now()
	return s.saveUtxo(utxo)
}
