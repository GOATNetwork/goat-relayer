package wallet

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/state"
	log "github.com/sirupsen/logrus"
)

// utxoReconcileMaxTipAge bounds how old the Bitcoin node's tip may be before its
// "unspent" answers are no longer trusted: a lagging node can report an output
// as unspent although the network already spent it.
const utxoReconcileMaxTipAge = 2 * time.Hour

const chainTipReportKey = "chain-tip"

type reconcileChain interface {
	GetTxOut(txid string, vout uint32, includeMempool bool) (*btcjson.GetTxOutResult, error)
	GetBlockCount() (int64, error)
	GetBlockHash(height int64) (*chainhash.Hash, error)
	GetBlockHeader(blockHash *chainhash.Hash) (*wire.BlockHeader, error)
}

// UtxoReconciler finds UTXOs stuck in pending although no in-flight send order
// uses them, and, once Bitcoin confirms they are still unspent, restores them
// to spendable. A stuck pending UTXO makes this node refuse every send order
// that selects it, which blocks withdrawals when its signature is needed.
//
// In dryrun mode it only logs what it would restore; in apply mode it updates
// the wallet database. Outputs that are not provably unspent are only logged.
// A finding is logged as a warning when first seen or when its reason changes;
// repeats are logged at debug level.
type UtxoReconciler struct {
	state            *state.State
	chain            reconcileChain
	mode             string
	interval         time.Duration
	minAge           time.Duration
	minConfirmations int64
	maxTipAge        time.Duration
	now              func() time.Time

	reported map[string]string
}

type utxoReconcileSummary struct {
	candidates     int
	restored       int
	wouldRestore   int
	skipped        int
	stoppedForSync bool
	staleChainTip  bool
}

func NewUtxoReconciler(st *state.State, chain reconcileChain) *UtxoReconciler {
	return &UtxoReconciler{
		state:            st,
		chain:            chain,
		mode:             config.AppConfig.UtxoReconcileMode,
		interval:         config.AppConfig.UtxoReconcileInterval,
		minAge:           config.AppConfig.UtxoReconcileMinAge,
		minConfirmations: int64(config.AppConfig.BTCConfirmations),
		maxTipAge:        utxoReconcileMaxTipAge,
		now:              time.Now,
		reported:         make(map[string]string),
	}
}

func (r *UtxoReconciler) Start(ctx context.Context) {
	if r.mode == config.UtxoReconcileModeOff {
		log.Info("UtxoReconciler disabled")
		return
	}
	log.Infof("UtxoReconciler started, mode: %s, interval: %v, min age: %v, min confirmations: %d, max chain tip age: %v",
		r.mode, r.interval, r.minAge, r.minConfirmations, r.maxTipAge)

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

func (r *UtxoReconciler) syncing() bool {
	return r.state.GetBtcHead().Syncing || r.state.GetL2Info().Syncing
}

func (r *UtxoReconciler) reconcileOnce() utxoReconcileSummary {
	summary := utxoReconcileSummary{}

	if r.syncing() {
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
	r.forgetResolved(candidates)
	if len(candidates) == 0 {
		return summary
	}

	if reason, fresh := r.checkChainTipFresh(now); !fresh {
		r.report(chainTipReportKey, "stale", fmt.Sprintf("UtxoReconciler pass skipped, %d candidates left unchanged: %s", len(candidates), reason))
		summary.staleChainTip = true
		summary.skipped = len(candidates)
		return summary
	}
	delete(r.reported, chainTipReportKey)

	newFindings := 0
	for i, utxo := range candidates {
		outpoint := fmt.Sprintf("%s:%d", utxo.Txid, utxo.OutIndex)

		category, evidence, unspent := r.checkUnspentOnChain(utxo)
		if !unspent {
			if r.report(outpoint, category, fmt.Sprintf("UtxoReconciler orphan pending utxo %s (id %d, amount %d) left unchanged: %s",
				outpoint, utxo.ID, utxo.Amount, evidence)) {
				newFindings++
			}
			summary.skipped++
			continue
		}

		if r.mode != config.UtxoReconcileModeApply {
			if r.report(outpoint, "would-restore", fmt.Sprintf("UtxoReconciler [dryrun] would restore orphan pending utxo %s (id %d, amount %d): %s",
				outpoint, utxo.ID, utxo.Amount, evidence)) {
				newFindings++
			}
			summary.wouldRestore++
			continue
		}

		if r.syncing() {
			log.Infof("UtxoReconciler stopped, BTC or L2 started syncing during the pass, %d candidates left for the next pass", len(candidates)-i)
			summary.stoppedForSync = true
			summary.skipped += len(candidates) - i
			break
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
		delete(r.reported, outpoint)
		log.Warnf("UtxoReconciler restored orphan pending utxo %s (id %d, amount %d): pending -> %s, %s",
			outpoint, utxo.ID, utxo.Amount, newStatus, evidence)
		summary.restored++
	}

	logf := log.Debugf
	if summary.restored > 0 || newFindings > 0 {
		logf = log.Infof
	}
	logf("UtxoReconciler pass done, mode: %s, candidates: %d, restored: %d, would restore: %d, skipped: %d",
		r.mode, summary.candidates, summary.restored, summary.wouldRestore, summary.skipped)
	return summary
}

// report logs msg as a warning the first time key is seen with category, and at
// debug level while the category stays the same. It returns true for a warning.
func (r *UtxoReconciler) report(key, category, msg string) bool {
	if r.reported[key] == category {
		log.Debug(msg)
		return false
	}
	r.reported[key] = category
	log.Warn(msg)
	return true
}

// forgetResolved drops findings of outpoints that are no longer candidates, so
// they are reported again if they ever come back.
func (r *UtxoReconciler) forgetResolved(candidates []*db.Utxo) {
	current := make(map[string]struct{}, len(candidates))
	for _, utxo := range candidates {
		current[fmt.Sprintf("%s:%d", utxo.Txid, utxo.OutIndex)] = struct{}{}
	}
	for key := range r.reported {
		if key == chainTipReportKey {
			continue
		}
		if _, ok := current[key]; !ok {
			delete(r.reported, key)
		}
	}
}

// checkChainTipFresh reports whether the Bitcoin node's tip is recent enough
// for its view of unspent outputs to be trusted.
func (r *UtxoReconciler) checkChainTipFresh(now time.Time) (string, bool) {
	height, err := r.chain.GetBlockCount()
	if err != nil {
		return fmt.Sprintf("get block count error: %v", err), false
	}
	hash, err := r.chain.GetBlockHash(height)
	if err != nil {
		return fmt.Sprintf("get block hash at %d error: %v", height, err), false
	}
	header, err := r.chain.GetBlockHeader(hash)
	if err != nil {
		return fmt.Sprintf("get block header %s error: %v", hash, err), false
	}
	age := now.Sub(header.Timestamp)
	if age > r.maxTipAge {
		return fmt.Sprintf("Bitcoin node tip %d (%s) is %v old, more than %v; the node may be behind the network",
			height, hash, age.Truncate(time.Second), r.maxTipAge), false
	}
	return "", true
}

// checkUnspentOnChain reports whether Bitcoin shows utxo as unspent (including
// mempool spends), sufficiently confirmed and with the recorded amount. The
// category identifies the reason, so a repeated finding is not re-reported.
func (r *UtxoReconciler) checkUnspentOnChain(utxo *db.Utxo) (category string, evidence string, unspent bool) {
	if utxo.OutIndex < 0 {
		return "invalid-index", fmt.Sprintf("invalid out index %d", utxo.OutIndex), false
	}
	txOut, err := r.chain.GetTxOut(utxo.Txid, uint32(utxo.OutIndex), true)
	if err != nil {
		return "rpc-error", fmt.Sprintf("gettxout error: %v", err), false
	}
	if txOut == nil {
		return "not-unspent", "not an unspent output on chain (spent, spent in mempool or unknown), needs manual review", false
	}
	if txOut.Confirmations < r.minConfirmations {
		return "shallow", fmt.Sprintf("only %d confirmations, need %d", txOut.Confirmations, r.minConfirmations), false
	}
	amount, err := btcutil.NewAmount(txOut.Value)
	if err != nil {
		return "invalid-value", fmt.Sprintf("invalid on-chain value %v: %v", txOut.Value, err), false
	}
	if int64(amount) != utxo.Amount {
		return "amount-mismatch", fmt.Sprintf("on-chain amount %d differs from recorded amount %d", int64(amount), utxo.Amount), false
	}
	return "unspent", fmt.Sprintf("unspent on chain with %d confirmations at best block %s", txOut.Confirmations, txOut.BestBlock), true
}
