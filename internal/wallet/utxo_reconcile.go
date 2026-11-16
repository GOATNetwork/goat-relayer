package wallet

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/state"
	log "github.com/sirupsen/logrus"
)

type txOutFetcher interface {
	GetTxOut(txid string, vout uint32, includeMempool bool) (*btcjson.GetTxOutResult, error)
}

// UtxoReconciler finds UTXOs stuck in pending although no in-flight send order
// uses them, and, once Bitcoin confirms they are still unspent, restores them
// to spendable. A stuck pending UTXO makes this node refuse every send order
// that selects it, which blocks withdrawals when its signature is needed.
//
// In dryrun mode it only logs what it would restore; in apply mode it updates
// the wallet database. Outputs that are not provably unspent are only logged.
type UtxoReconciler struct {
	state            *state.State
	chain            txOutFetcher
	mode             string
	interval         time.Duration
	minAge           time.Duration
	minConfirmations int64
	now              func() time.Time
}

type utxoReconcileSummary struct {
	candidates   int
	restored     int
	wouldRestore int
	skipped      int
}

func NewUtxoReconciler(st *state.State, chain txOutFetcher) *UtxoReconciler {
	return &UtxoReconciler{
		state:            st,
		chain:            chain,
		mode:             config.AppConfig.UtxoReconcileMode,
		interval:         config.AppConfig.UtxoReconcileInterval,
		minAge:           config.AppConfig.UtxoReconcileMinAge,
		minConfirmations: int64(config.AppConfig.BTCConfirmations),
		now:              time.Now,
	}
}

func (r *UtxoReconciler) Start(ctx context.Context) {
	if r.mode == config.UtxoReconcileModeOff {
		log.Info("UtxoReconciler disabled")
		return
	}
	log.Infof("UtxoReconciler started, mode: %s, interval: %v, min age: %v, min confirmations: %d",
		r.mode, r.interval, r.minAge, r.minConfirmations)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reconcileOnce()
		}
	}
}

func (r *UtxoReconciler) reconcileOnce() utxoReconcileSummary {
	summary := utxoReconcileSummary{}

	if r.state.GetBtcHead().Syncing || r.state.GetL2Info().Syncing {
		log.Debug("UtxoReconciler skipped, BTC or L2 is syncing")
		return summary
	}

	now := r.now()
	candidates, err := r.state.ListOrphanPendingUtxos(r.minAge, now)
	if err != nil {
		log.Errorf("UtxoReconciler list orphan pending utxos error: %v", err)
		return summary
	}
	summary.candidates = len(candidates)

	for _, utxo := range candidates {
		outpoint := fmt.Sprintf("%s:%d", utxo.Txid, utxo.OutIndex)

		evidence, unspent := r.checkUnspentOnChain(utxo)
		if !unspent {
			log.Warnf("UtxoReconciler orphan pending utxo %s (id %d, amount %d) left unchanged: %s",
				outpoint, utxo.ID, utxo.Amount, evidence)
			summary.skipped++
			continue
		}

		if r.mode != config.UtxoReconcileModeApply {
			log.Warnf("UtxoReconciler [dryrun] would restore orphan pending utxo %s (id %d, amount %d): %s",
				outpoint, utxo.ID, utxo.Amount, evidence)
			summary.wouldRestore++
			continue
		}

		newStatus, err := r.state.RestoreOrphanPendingUtxo(utxo.Txid, utxo.OutIndex, r.minAge, now)
		if err != nil {
			log.Errorf("UtxoReconciler restore utxo %s (id %d) error: %v", outpoint, utxo.ID, err)
			summary.skipped++
			continue
		}
		if newStatus == "" {
			log.Infof("UtxoReconciler utxo %s (id %d) no longer an orphan pending utxo, left unchanged", outpoint, utxo.ID)
			summary.skipped++
			continue
		}
		log.Warnf("UtxoReconciler restored orphan pending utxo %s (id %d, amount %d): pending -> %s, %s",
			outpoint, utxo.ID, utxo.Amount, newStatus, evidence)
		summary.restored++
	}

	if summary.candidates > 0 {
		log.Infof("UtxoReconciler pass done, mode: %s, candidates: %d, restored: %d, would restore: %d, skipped: %d",
			r.mode, summary.candidates, summary.restored, summary.wouldRestore, summary.skipped)
	}
	return summary
}

// checkUnspentOnChain reports whether Bitcoin shows utxo as unspent (including
// mempool spends), sufficiently confirmed and with the recorded amount.
func (r *UtxoReconciler) checkUnspentOnChain(utxo *db.Utxo) (string, bool) {
	if utxo.OutIndex < 0 {
		return fmt.Sprintf("invalid out index %d", utxo.OutIndex), false
	}
	txOut, err := r.chain.GetTxOut(utxo.Txid, uint32(utxo.OutIndex), true)
	if err != nil {
		return fmt.Sprintf("gettxout error: %v", err), false
	}
	if txOut == nil {
		return "not an unspent output on chain (spent, spent in mempool or unknown), needs manual review", false
	}
	if txOut.Confirmations < r.minConfirmations {
		return fmt.Sprintf("only %d confirmations, need %d", txOut.Confirmations, r.minConfirmations), false
	}
	amount, err := btcutil.NewAmount(txOut.Value)
	if err != nil {
		return fmt.Sprintf("invalid on-chain value %v: %v", txOut.Value, err), false
	}
	if int64(amount) != utxo.Amount {
		return fmt.Sprintf("on-chain amount %d differs from recorded amount %d", int64(amount), utxo.Amount), false
	}
	return fmt.Sprintf("unspent on chain with %d confirmations at best block %s", txOut.Confirmations, txOut.BestBlock), true
}
