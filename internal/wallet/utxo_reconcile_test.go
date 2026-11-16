package wallet

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type fakeTxOutFetcher struct {
	outputs map[string]*btcjson.GetTxOutResult
	errs    map[string]error
}

func (f *fakeTxOutFetcher) GetTxOut(txid string, vout uint32, includeMempool bool) (*btcjson.GetTxOutResult, error) {
	key := fmt.Sprintf("%s:%d", txid, vout)
	if err, ok := f.errs[key]; ok {
		return nil, err
	}
	return f.outputs[key], nil
}

const reconcileTestAmount = int64(28153287)

func unspentOutput(confirmations int64, sats int64) *btcjson.GetTxOutResult {
	return &btcjson.GetTxOutResult{
		BestBlock:     "000000000000000000017b",
		Confirmations: confirmations,
		Value:         btcutil.Amount(sats).ToBTC(),
	}
}

func setupReconcileTest(t *testing.T, mode string) (*UtxoReconciler, *state.State, *gorm.DB) {
	t.Setenv("DB_DIR", t.TempDir())
	config.InitConfig()
	logrus.SetLevel(logrus.ErrorLevel)
	dbm := db.NewDatabaseManager()
	st := state.InitializeState(dbm)
	walletDb := dbm.GetWalletDB()
	now := time.Now()

	for _, txid := range []string{"healthy", "spent", "shallow", "mismatch", "rpc-error"} {
		utxo := &db.Utxo{
			Txid:          txid,
			OutIndex:      1,
			Amount:        reconcileTestAmount,
			Receiver:      "bc1qreceiver",
			WalletVersion: "1",
			Source:        db.UTXO_SOURCE_WITHDRAWAL,
			ReceiverType:  db.WALLET_TYPE_P2WPKH,
			Status:        db.UTXO_STATUS_PENDING,
		}
		require.NoError(t, walletDb.Create(utxo).Error)
		require.NoError(t, walletDb.Model(&db.Utxo{}).Where("id = ?", utxo.ID).UpdateColumn("updated_at", now.Add(-2*time.Hour)).Error)
	}

	chain := &fakeTxOutFetcher{
		outputs: map[string]*btcjson.GetTxOutResult{
			"healthy:1":  unspentOutput(120, reconcileTestAmount),
			"shallow:1":  unspentOutput(2, reconcileTestAmount),
			"mismatch:1": unspentOutput(120, reconcileTestAmount-1),
		},
		errs: map[string]error{"rpc-error:1": errors.New("connection refused")},
	}

	reconciler := &UtxoReconciler{
		state:            st,
		chain:            chain,
		mode:             mode,
		interval:         10 * time.Minute,
		minAge:           30 * time.Minute,
		minConfirmations: 6,
		now:              func() time.Time { return now },
	}
	return reconciler, st, walletDb
}

func statusOf(t *testing.T, walletDb *gorm.DB, txid string) string {
	t.Helper()
	var utxo db.Utxo
	require.NoError(t, walletDb.Where("txid = ? and out_index = ?", txid, 1).First(&utxo).Error)
	return utxo.Status
}

func TestUtxoReconcilerDryRunChangesNothing(t *testing.T) {
	reconciler, _, walletDb := setupReconcileTest(t, config.UtxoReconcileModeDryRun)

	summary := reconciler.reconcileOnce()

	require.Equal(t, utxoReconcileSummary{candidates: 5, wouldRestore: 1, skipped: 4}, summary)
	for _, txid := range []string{"healthy", "spent", "shallow", "mismatch", "rpc-error"} {
		require.Equal(t, db.UTXO_STATUS_PENDING, statusOf(t, walletDb, txid), txid)
	}
}

func TestUtxoReconcilerApplyRestoresOnlyProvablyUnspent(t *testing.T) {
	reconciler, _, walletDb := setupReconcileTest(t, config.UtxoReconcileModeApply)

	summary := reconciler.reconcileOnce()

	require.Equal(t, utxoReconcileSummary{candidates: 5, restored: 1, skipped: 4}, summary)
	require.Equal(t, db.UTXO_STATUS_CONFIRMED, statusOf(t, walletDb, "healthy"))
	for _, txid := range []string{"spent", "shallow", "mismatch", "rpc-error"} {
		require.Equal(t, db.UTXO_STATUS_PENDING, statusOf(t, walletDb, txid), txid)
	}

	second := reconciler.reconcileOnce()
	require.Equal(t, utxoReconcileSummary{candidates: 4, skipped: 4}, second)
}

func TestUtxoReconcilerSkipsWhileSyncing(t *testing.T) {
	reconciler, st, walletDb := setupReconcileTest(t, config.UtxoReconcileModeApply)
	st.UpdateBtcSyncing(true)

	summary := reconciler.reconcileOnce()

	require.Equal(t, utxoReconcileSummary{}, summary)
	require.Equal(t, db.UTXO_STATUS_PENDING, statusOf(t, walletDb, "healthy"))
}
