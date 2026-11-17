package state

import (
	"errors"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	"gorm.io/gorm"
)

// inFlightOrderStatuses are the send order statuses in which the order's inputs
// are legitimately reserved (status pending) and must not be touched.
var inFlightOrderStatuses = []string{
	db.ORDER_STATUS_AGGREGATING,
	db.ORDER_STATUS_INIT,
	db.ORDER_STATUS_PENDING,
	db.ORDER_STATUS_RBF_REQUEST,
	db.ORDER_STATUS_UNCONFIRM,
}

// ListOrphanPendingUtxos returns UTXOs that have been pending for at least
// minAge and are not an input of any in-flight send order. Such a UTXO cannot
// be spent by any order, yet blocks every new order that selects it.
func (s *State) ListOrphanPendingUtxos(minAge time.Duration, now time.Time) ([]*db.Utxo, error) {
	s.walletMu.RLock()
	defer s.walletMu.RUnlock()

	utxos, err := s.getUtxoByStatuses(nil, "id asc", db.UTXO_STATUS_PENDING)
	if err != nil {
		return nil, err
	}

	orphans := make([]*db.Utxo, 0)
	for _, utxo := range utxos {
		if now.Sub(utxo.UpdatedAt) < minAge {
			continue
		}
		inUse, err := s.isUtxoInFlight(nil, utxo.Txid, utxo.OutIndex)
		if err != nil {
			return nil, err
		}
		if !inUse {
			orphans = append(orphans, utxo)
		}
	}
	return orphans, nil
}

// RestoreOrphanPendingUtxo re-checks, in one transaction, that txid:outIndex is
// still an orphan pending UTXO and restores it to the spendable status AddUtxo
// would have stored: processed for a known deposit, confirmed otherwise.
// It returns the new status, or "" if the UTXO no longer qualifies.
// The caller is responsible for having verified on chain that it is unspent.
func (s *State) RestoreOrphanPendingUtxo(txid string, outIndex int, minAge time.Duration, now time.Time) (string, error) {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	newStatus := ""
	err := s.dbm.GetWalletDB().Transaction(func(tx *gorm.DB) error {
		utxo, err := s.getUtxo(tx, txid, outIndex)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if utxo.Status != db.UTXO_STATUS_PENDING || now.Sub(utxo.UpdatedAt) < minAge {
			return nil
		}
		inUse, err := s.isUtxoInFlight(tx, txid, outIndex)
		if err != nil {
			return err
		}
		if inUse {
			return nil
		}

		status := db.UTXO_STATUS_CONFIRMED
		var depositCount int64
		err = tx.Model(&db.DepositResult{}).Where("txid = ? and tx_out = ?", txid, outIndex).Count(&depositCount).Error
		if err != nil {
			return err
		}
		if depositCount > 0 {
			status = db.UTXO_STATUS_PROCESSED
		}

		result := tx.Model(&db.Utxo{}).
			Where("id = ? and status = ?", utxo.ID, db.UTXO_STATUS_PENDING).
			Updates(map[string]interface{}{"status": status, "updated_at": now})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 1 {
			newStatus = status
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return newStatus, nil
}

// isUtxoInFlight reports whether txid:outIndex is an input of an in-flight send order.
func (s *State) isUtxoInFlight(tx *gorm.DB, txid string, outIndex int) (bool, error) {
	if tx == nil {
		tx = s.dbm.GetWalletDB()
	}
	var count int64
	err := tx.Model(&db.Vin{}).
		Joins("JOIN send_orders ON send_orders.order_id = vins.order_id").
		Where("vins.txid = ? and vins.out_index = ? and send_orders.status in (?)", txid, outIndex, inFlightOrderStatuses).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
