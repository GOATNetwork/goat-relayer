package wallet

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type fakeReconcileChain struct {
	outputs  map[string]*btcjson.GetTxOutResult
	errs     map[string]error
	tipTime  time.Time
	onTxOut  func(key string)
	tipCalls int
}

func (f *fakeReconcileChain) GetTxOut(txid string, vout uint32, includeMempool bool) (*btcjson.GetTxOutResult, error) {
	key := fmt.Sprintf("%s:%d", txid, vout)
	if f.onTxOut != nil {
		f.onTxOut(key)
	}
	if err, ok := f.errs[key]; ok {
		return nil, err
	}
	return f.outputs[key], nil
}

func (f *fakeReconcileChain) GetBlockCount() (int64, error) {
	f.tipCalls++
	return 976200, nil
}

func (f *fakeReconcileChain) GetBlockHash(height int64) (*chainhash.Hash, error) {
	return &chainhash.Hash{}, nil
}

func (f *fakeReconcileChain) GetBlockHeader(blockHash *chainhash.Hash) (*wire.BlockHeader, error) {
	return &wire.BlockHeader{Timestamp: f.tipTime}, nil
}

const reconcileTestAmount = int64(28153287)

var reconcileTestTxids = []string{"healthy", "spent", "shallow", "mismatch", "rpc-error"}

func unspentOutput(confirmations int64, sats int64) *btcjson.GetTxOutResult {
	return &btcjson.GetTxOutResult{
		BestBlock:     "000000000000000000017b",
		Confirmations: confirmations,
		Value:         btcutil.Amount(sats).ToBTC(),
	}
}

func setupReconcileTest(t *testing.T, mode string) (*UtxoReconciler, *state.State, *gorm.DB, *fakeReconcileChain) {
	t.Setenv("DB_DIR", t.TempDir())
	config.InitConfig()
	logrus.SetLevel(logrus.ErrorLevel)
	dbm := db.NewDatabaseManager()
	st := state.InitializeState(dbm)
	walletDb := dbm.GetWalletDB()
	now := time.Now()

	for _, txid := range reconcileTestTxids {
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

	chain := &fakeReconcileChain{
		outputs: map[string]*btcjson.GetTxOutResult{
			"healthy:1":  unspentOutput(120, reconcileTestAmount),
			"shallow:1":  unspentOutput(2, reconcileTestAmount),
			"mismatch:1": unspentOutput(120, reconcileTestAmount-1),
		},
		errs:    map[string]error{"rpc-error:1": errors.New("connection refused")},
		tipTime: now.Add(-5 * time.Minute),
	}

	reconciler := &UtxoReconciler{
		state:            st,
		chain:            chain,
		mode:             mode,
		interval:         10 * time.Minute,
		minAge:           30 * time.Minute,
		minConfirmations: 6,
		maxTipAge:        utxoReconcileMaxTipAge,
		now:              func() time.Time { return now },
		reported:         make(map[string]string),
	}
	return reconciler, st, walletDb, chain
}

func statusOf(t *testing.T, walletDb *gorm.DB, txid string) string {
	t.Helper()
	var utxo db.Utxo
	require.NoError(t, walletDb.Where("txid = ? and out_index = ?", txid, 1).First(&utxo).Error)
	return utxo.Status
}

func requireAllPending(t *testing.T, walletDb *gorm.DB, txids ...string) {
	t.Helper()
	for _, txid := range txids {
		require.Equal(t, db.UTXO_STATUS_PENDING, statusOf(t, walletDb, txid), txid)
	}
}

func TestUtxoReconcilerDryRunChangesNothing(t *testing.T) {
	reconciler, _, walletDb, _ := setupReconcileTest(t, config.UtxoReconcileModeDryRun)

	summary := reconciler.reconcileOnce()

	require.Equal(t, utxoReconcileSummary{candidates: 5, wouldRestore: 1, skipped: 4}, summary)
	requireAllPending(t, walletDb, reconcileTestTxids...)
}

func TestUtxoReconcilerApplyRestoresOnlyProvablyUnspent(t *testing.T) {
	reconciler, _, walletDb, _ := setupReconcileTest(t, config.UtxoReconcileModeApply)

	summary := reconciler.reconcileOnce()

	require.Equal(t, utxoReconcileSummary{candidates: 5, restored: 1, skipped: 4}, summary)
	require.Equal(t, db.UTXO_STATUS_CONFIRMED, statusOf(t, walletDb, "healthy"))
	requireAllPending(t, walletDb, "spent", "shallow", "mismatch", "rpc-error")

	second := reconciler.reconcileOnce()
	require.Equal(t, utxoReconcileSummary{candidates: 4, skipped: 4}, second)
}

func TestUtxoReconcilerSkipsWhileSyncing(t *testing.T) {
	reconciler, st, walletDb, _ := setupReconcileTest(t, config.UtxoReconcileModeApply)
	st.UpdateBtcSyncing(true)

	summary := reconciler.reconcileOnce()

	require.Equal(t, utxoReconcileSummary{}, summary)
	require.Equal(t, db.UTXO_STATUS_PENDING, statusOf(t, walletDb, "healthy"))
}

func TestUtxoReconcilerStopsWhenSyncStartsDuringPass(t *testing.T) {
	reconciler, st, walletDb, chain := setupReconcileTest(t, config.UtxoReconcileModeApply)
	chain.onTxOut = func(key string) {
		if key == "healthy:1" {
			st.UpdateBtcSyncing(true)
		}
	}

	summary := reconciler.reconcileOnce()

	require.True(t, summary.stoppedForSync)
	require.Zero(t, summary.restored)
	require.Equal(t, db.UTXO_STATUS_PENDING, statusOf(t, walletDb, "healthy"))
}

func TestUtxoReconcilerSkipsWhenChainTipIsStale(t *testing.T) {
	reconciler, _, walletDb, chain := setupReconcileTest(t, config.UtxoReconcileModeApply)
	chain.tipTime = reconciler.now().Add(-3 * time.Hour)

	summary := reconciler.reconcileOnce()

	require.Equal(t, utxoReconcileSummary{candidates: 5, skipped: 5, staleChainTip: true}, summary)
	requireAllPending(t, walletDb, reconcileTestTxids...)
}

func TestUtxoReconcilerWarnsOncePerFinding(t *testing.T) {
	reconciler, _, _, chain := setupReconcileTest(t, config.UtxoReconcileModeDryRun)
	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.DebugLevel)
	hook := test.NewLocal(logger)
	t.Cleanup(func() { logger.ReplaceHooks(make(logrus.LevelHooks)); logger.SetLevel(logrus.ErrorLevel) })

	warnings := func() int {
		n := 0
		for _, entry := range hook.AllEntries() {
			if entry.Level == logrus.WarnLevel {
				n++
			}
		}
		hook.Reset()
		return n
	}

	reconciler.reconcileOnce()
	require.Equal(t, 5, warnings(), "first pass reports every candidate")

	reconciler.reconcileOnce()
	require.Equal(t, 0, warnings(), "unchanged findings are not reported again")

	chain.outputs["shallow:1"] = unspentOutput(120, reconcileTestAmount)
	reconciler.reconcileOnce()
	require.Equal(t, 1, warnings(), "a finding whose reason changed is reported again")
}
