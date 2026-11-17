package state

import (
	"testing"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func newReconcileTestState(t *testing.T) *State {
	t.Setenv("DB_DIR", t.TempDir())
	config.InitConfig()
	logrus.SetLevel(logrus.ErrorLevel)
	return InitializeState(db.NewDatabaseManager())
}

func insertTestUtxo(t *testing.T, s *State, txid string, outIndex int, status string, updatedAt time.Time) {
	t.Helper()
	walletDb := s.dbm.GetWalletDB()
	utxo := &db.Utxo{
		Txid:          txid,
		OutIndex:      outIndex,
		Amount:        28153287,
		Receiver:      "bc1qreceiver",
		WalletVersion: "1",
		Source:        db.UTXO_SOURCE_WITHDRAWAL,
		ReceiverType:  db.WALLET_TYPE_P2WPKH,
		Status:        status,
	}
	require.NoError(t, walletDb.Create(utxo).Error)
	require.NoError(t, walletDb.Model(&db.Utxo{}).Where("id = ?", utxo.ID).UpdateColumn("updated_at", updatedAt).Error)
}

func insertTestOrderSpending(t *testing.T, s *State, orderId string, orderStatus string, txid string, outIndex int) {
	t.Helper()
	walletDb := s.dbm.GetWalletDB()
	require.NoError(t, walletDb.Create(&db.SendOrder{
		OrderId:   orderId,
		Proposer:  "goat1proposer",
		Status:    orderStatus,
		OrderType: db.ORDER_TYPE_WITHDRAWAL,
		Txid:      "spend-" + orderId,
		UpdatedAt: time.Now(),
	}).Error)
	require.NoError(t, walletDb.Create(&db.Vin{
		OrderId:      orderId,
		Txid:         txid,
		OutIndex:     outIndex,
		ReceiverType: db.WALLET_TYPE_P2WPKH,
		Source:       db.UTXO_SOURCE_WITHDRAWAL,
		Status:       orderStatus,
		UpdatedAt:    time.Now(),
	}).Error)
}

func utxoStatus(t *testing.T, s *State, txid string, outIndex int) string {
	t.Helper()
	utxo, err := s.getUtxo(nil, txid, outIndex)
	require.NoError(t, err)
	return utxo.Status
}

func TestListOrphanPendingUtxos(t *testing.T) {
	s := newReconcileTestState(t)
	now := time.Now()
	old := now.Add(-2 * time.Hour)
	minAge := 30 * time.Minute

	insertTestUtxo(t, s, "orphan", 1, db.UTXO_STATUS_PENDING, old)
	insertTestUtxo(t, s, "inflight", 0, db.UTXO_STATUS_PENDING, old)
	insertTestOrderSpending(t, s, "order-aggregating", db.ORDER_STATUS_AGGREGATING, "inflight", 0)
	insertTestUtxo(t, s, "closed-order-only", 0, db.UTXO_STATUS_PENDING, old)
	insertTestOrderSpending(t, s, "order-closed", db.ORDER_STATUS_CLOSED, "closed-order-only", 0)
	insertTestUtxo(t, s, "too-young", 0, db.UTXO_STATUS_PENDING, now.Add(-5*time.Minute))
	insertTestUtxo(t, s, "confirmed", 0, db.UTXO_STATUS_CONFIRMED, old)

	orphans, err := s.ListOrphanPendingUtxos(minAge, now)
	require.NoError(t, err)

	got := make([]string, 0, len(orphans))
	for _, utxo := range orphans {
		got = append(got, utxo.Txid)
	}
	require.ElementsMatch(t, []string{"orphan", "closed-order-only"}, got)
}

func TestRestoreOrphanPendingUtxo(t *testing.T) {
	s := newReconcileTestState(t)
	now := time.Now()
	old := now.Add(-2 * time.Hour)
	minAge := 30 * time.Minute

	insertTestUtxo(t, s, "orphan", 1, db.UTXO_STATUS_PENDING, old)
	insertTestUtxo(t, s, "deposit", 0, db.UTXO_STATUS_PENDING, old)
	require.NoError(t, s.dbm.GetWalletDB().Create(&db.DepositResult{Txid: "deposit", TxOut: 0, Address: "0xevm", Amount: 28153287}).Error)
	insertTestUtxo(t, s, "inflight", 0, db.UTXO_STATUS_PENDING, old)
	insertTestOrderSpending(t, s, "order-pending", db.ORDER_STATUS_PENDING, "inflight", 0)
	insertTestUtxo(t, s, "too-young", 0, db.UTXO_STATUS_PENDING, now.Add(-5*time.Minute))

	status, err := s.RestoreOrphanPendingUtxo("orphan", 1, minAge, now)
	require.NoError(t, err)
	require.Equal(t, db.UTXO_STATUS_CONFIRMED, status)
	require.Equal(t, db.UTXO_STATUS_CONFIRMED, utxoStatus(t, s, "orphan", 1))

	status, err = s.RestoreOrphanPendingUtxo("orphan", 1, minAge, now)
	require.NoError(t, err)
	require.Empty(t, status, "an already restored utxo must not be touched again")

	status, err = s.RestoreOrphanPendingUtxo("deposit", 0, minAge, now)
	require.NoError(t, err)
	require.Equal(t, db.UTXO_STATUS_PROCESSED, status)
	require.Equal(t, db.UTXO_STATUS_PROCESSED, utxoStatus(t, s, "deposit", 0))

	status, err = s.RestoreOrphanPendingUtxo("inflight", 0, minAge, now)
	require.NoError(t, err)
	require.Empty(t, status)
	require.Equal(t, db.UTXO_STATUS_PENDING, utxoStatus(t, s, "inflight", 0))

	status, err = s.RestoreOrphanPendingUtxo("too-young", 0, minAge, now)
	require.NoError(t, err)
	require.Empty(t, status)
	require.Equal(t, db.UTXO_STATUS_PENDING, utxoStatus(t, s, "too-young", 0))

	status, err = s.RestoreOrphanPendingUtxo("missing", 0, minAge, now)
	require.NoError(t, err)
	require.Empty(t, status)
}
