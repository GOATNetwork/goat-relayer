# Goat Relayer Wallet
This document mainly describes the wallet management of Relayer, including spendable utxo, withdrawal application discovery, withdrawal processing, p2wsh consolidation, p2pkh consolidation, etc.

## GORM schema
```
Utxo: source (deposit|other), receiver_type (P2PKH P2SH P2WSH P2WPKH P2TR), status
|- source -> deposit, it contains P2PKH, P2WSH receiver_types
Withdraw: evm_tx_id, from (evm address), to (btc address), amount, status
|
SendOrder: an order to select utxo to process, withdrawal or consolidation
｜- operate -> init, sign, send to btc (pending, rbf-request), finalize (feedback to goat)
Vin: SendOrder in items, from utxo P2PKH type and status of confirmed or processed
|
Vout: SendOrder out items, contain change to self address
```

## State update
The status update mainly refers to the two-way status update of utxo and withdraw|deposit, in order to be compatible with the disorder of layer2 and btc listener of the newly added voter node

### * Btc Poller 
Step 1,
> check the utxo vouts from send order vin in Vin table

Step 2,
> save to Uxto with status of confirmed or spent

Step 3,
> check the utxo vins from send order vin in Vin table

Step 4
> save to Vin, Vout (sender is MPC) with status processed if not exists, and order id set to 'restore';  update Vin status to processed if exists, update SendOrder status to confirmed if not processed


### * Layer2 Listener
Step 1,
> detect user withdraw tx, save to Withdraw table

Step 2,
> update Withdraw table by event

Step 3,
> restore order id?, Vin?, Vout?

## Data flow
User Deposit 1 
> Deposit -> Utxo (P2WPKH)

User Deposit 0 
> Deposit -> Utxo (P2WSH)

Other Transfer *
> Transfer -> Utxo (P2PKH)

Consolidation * child collection of Other Transfer
> Utxo (P2WSH|P2WPKH|P2PKH) -> Utxo (P2WPKH)

Withdrawal
> Utxo (P2PKH) ->  Withdraw + Utxo (P2PKH)

## Consolidation
- UTXO Value < 0.5 BTC
- Total >= 500
- Max Vin 50
- Vout 1 P2WPKH
- ==
- Max Queue 10
- Max Network Fee qurom 200 sat/vbyte

## Withdrawal
- Max Vout 150
- Max Vin 50
- NetworkFee <= User TxPrice
- Single UTXO value <= 50 BTC (sum wallet value)
- Add a smallest value UTXO
- ==
- Max Queue 10
- Max Network Fee qurom 500 sat/vbyte

## Pending UTXO Reconciliation
A UTXO is set to `pending` when a send order reserves it as an input. If it stays `pending` while no in-flight send order (`aggregating`, `init`, `pending`, `rbf-request`, `unconfirm`) uses it, the node refuses every new order that selects it (`utxo status can not be make withdrawal or consolidation`), which can block withdrawals.

The UTXO reconciler runs every `UTXO_RECONCILE_INTERVAL` and is skipped while BTC or L2 is syncing. A candidate is an orphan `pending` UTXO whose `updated_at` is older than `UTXO_RECONCILE_MIN_AGE`. Note that the age counts from the UTXO's last update, not from the moment it became orphaned, so a UTXO that was pending long enough may be restored on the next pass after its order closes.

Before checking candidates, the reconciler requires the Bitcoin node's tip to be at most 2h old; otherwise the whole pass is skipped, because a lagging node can report an already spent output as unspent. For each candidate it calls `gettxout` (mempool included):
- unspent, at least `BTC_CONFIRMATIONS` confirmations and same amount: restore to `confirmed` (`processed` for a known deposit). The BTC/L2 sync state is checked again right before each restore, and the pass stops if syncing started.
- anything else (spent, unknown, too few confirmations, amount mismatch, RPC error): log only, leave for manual review

A finding is logged as a warning when first seen or when its reason changes; repeats are logged at debug level.

`UTXO_RECONCILE_MODE`:
- `dryrun` (default): log `would restore` lines, change nothing
- `apply`: restore, logging each change with its on-chain evidence
- `off`: disabled

`UTXO_RECONCILE_INTERVAL` (default `10m`, minimum `1m`) and `UTXO_RECONCILE_MIN_AGE` (default `30m`, minimum `10m`) must carry a unit; a bare number such as `600` is rejected at startup.

### Rollout and acceptance
The reconciler only changes the local node's database. A withdrawal stays blocked while any voter needed for the signing threshold still holds the UTXO as `pending`, so a successful deployment alone does not mean the incident is resolved.
1. Deploy every node with `dryrun`. After at least one interval, collect `UtxoReconciler` log lines from **every** node and list which nodes report `would restore` for the target outpoint.
2. Before switching to `apply`, check each of those nodes' Bitcoin RPC: `getblockchaininfo` shows `blocks == headers` and `initialblockdownload: false`, and the tip is recent. Do not rely on the relayer's own `Syncing=false`, which only means it has caught up with its own RPC node.
3. Switch only those nodes to `apply` and wait for `restored ... pending -> confirmed` on each of them.
4. Verify on each of them that the UTXO is no longer `pending` in `wallet_order.db`, then verify the blocked withdrawal moves to `PROCESSING` and `PAID` on chain. Only then treat the incident as resolved.

Not covered: a UTXO reserved by an order that stays in an in-flight status (for example an order whose other input is already spent on chain) counts as in use and is never restored by the reconciler; such orders need separate handling.
