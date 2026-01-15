# RBF (Replace-By-Fee) Mechanism Documentation

## Overview

When the Relayer broadcasts a transaction to the BTC network, it may encounter UTXO conflict errors (`bad-txns-inputs-missingorspent`, error code -25). This indicates that the UTXOs used by the transaction have already been spent by another transaction. The RBF mechanism handles this situation with different strategies based on order type.

## Trigger Conditions

```
BTC RPC SendRawTransaction returns error:
- Code: -25 (ErrRPCVerify)
- Message: "bad-txns-inputs-missingorspent" / "txn-mempool-conflict" / "missing-inputs"
```

## Order Type Differences

### Safebox Orders - Complete Rollback Strategy

**Characteristics:**
- Timelock address is calculated based on current block time
- Block time changes during re-aggregation cause timelock address changes
- Therefore, both vin and vout will change completely

**Processing Flow:**
```
1. Detect UTXO conflict
2. Call CleanInitializedNeedRbfWithdrawByOrderId
3. Check each UTXO status:
   - If spent → mark as UTXO_STATUS_SPENT
   - If not spent → restore to UTXO_STATUS_PROCESSED
4. Close current order (ORDER_STATUS_CLOSED)
5. Reset safebox_task status to received_ok
6. Next initWithdrawSig round will re-aggregate and generate a new transaction
```

**Database State Changes:**
```
send_order: init/pending → closed
vin/vout: * → closed
safebox_task: init/init_ok → received_ok
utxo: updated to spent or processed based on chain status
```

### Withdrawal Orders - RBF Replacement Strategy

**Characteristics:**
- Vout must remain consistent with the original ProcessWithdrawalV2 submission
- Consensus layer associates original withdrawal IDs through Pid
- Only vin (UTXO selection) and fee can change
- Must submit MsgReplaceWithdrawalV2 to goat consensus layer

**Processing Flow:**
```
1. Detect UTXO conflict
2. Call CleanInitializedNeedRbfWithdrawByOrderId
3. Check each UTXO status
4. Mark order as ORDER_STATUS_RBF_REQUEST (preserve Pid)
5. initRbfWithdrawSig detects RBF order
6. Select new UTXOs, calculate new fee
7. Create new transaction (same withdrawals, different vins)
8. Aggregate through BLS signature
9. Submit MsgReplaceWithdrawalV2 to consensus layer
```

**Database State Changes:**
```
send_order: init/pending → rbf-request → (new order created)
vin/vout: * → closed
withdraw: pending → aggregating
utxo: updated based on chain status
```

## Goat Consensus Layer Validation Rules

### ReplaceWithdrawalV2 Validation (`goat/x/bitcoin/keeper/tx.go:289`)

```go
func (k msgServer) replaceWithdrawal(ctx context.Context, req types.ReplaceWithdrawalMsger) error {
    // 1. Get Processing record by Pid
    processing, err := k.Processing.Get(sdkctx, req.GetPid())

    // 2. Fee must increase
    if processing.Fee >= req.GetNewTxFee() {
        return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "new tx fee is less than before")
    }

    // 3. Txid must be unique (cannot resubmit same transaction)
    for _, item := range processing.Txid {
        if bytes.Equal(item, txid) {
            return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "the tx doesn't have any change")
        }
    }

    // 4. Output count must match (with/without change allowed)
    txoutLen, withdrawalLen := len(tx.TxOut), len(processing.Withdrawals)
    if txoutLen != withdrawalLen && txoutLen != withdrawalLen+1 {
        return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "invalid tx output size for withdrawals")
    }

    // 5. Iterate original withdrawals and validate each output
    for idx, wid := range processing.Withdrawals {
        withdrawal, err := k.Withdrawals.Get(sdkctx, wid)

        // Status must be PROCESSING
        if withdrawal.Status != types.WITHDRAWAL_STATUS_PROCESSING {
            return errorsmod.Wrapf(...)
        }

        // txPrice must be <= MaxTxPrice
        if txPrice > float64(withdrawal.MaxTxPrice) {
            return errorsmod.Wrapf(...)
        }

        // Output script must strictly match original withdrawal address
        if !bytes.Equal(outputScript, txout.PkScript) {
            return errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "witdhrawal %d script not matched", wid)
        }
    }

    // 6. Change output must be sent to current relayer pubkey address
    if txoutLen != withdrawalLen {
        change := tx.TxOut[withdrawalLen]
        pubkey, _ := k.Pubkey.Get(ctx)
        if !types.VerifySystemAddressScript(&pubkey, change.PkScript) {
            return errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "give change to not a latest relayer pubkey")
        }
    }
}
```

### Processing Struct

```go
type Processing struct {
    Txid        [][]byte   // List of all RBF transaction txids (history)
    Output      []TxOuptut // Output amounts for each transaction
    Withdrawals []uint64   // Associated withdrawal ID list (immutable)
    Fee         uint64     // Current fee
}
```

### Key Constraints

| Constraint | Description |
|------------|-------------|
| `newFee > oldFee` | Fee must increase |
| `txPrice <= MinMaxTxPrice` | Cannot exceed any withdrawal's MaxTxPrice |
| `txid unique` | Each RBF must produce a different transaction |
| `vout order unchanged` | Output scripts must match original withdrawals order |
| `vout count constraint` | Must equal withdrawalLen or withdrawalLen+1 |

## Fee Optimization Strategy

### Constraints

```
1. newFee > oldFee           (RBF requirement)
2. txPrice <= minMaxTxPrice  (user limit)
   where txPrice = fee / vbytes
   vbytes = stripped_size + witness_size / 4
```

### Calculation Logic

```go
// 1. Find minimum MaxTxPrice in the batch
var minMaxTxPrice uint64 = ^uint64(0)
for _, withdraw := range withdraws {
    if withdraw.TxPrice < minMaxTxPrice {
        minMaxTxPrice = withdraw.TxPrice
    }
}

// 2. Calculate vbytes
vbytes := float64(tx.SerializeSizeStripped()) + float64(witnessSize)/4.0

// 3. Calculate maximum allowed fee
maxAllowedFee := uint64(float64(minMaxTxPrice) * vbytes)

// 4. Calculate minimum required fee
minRequiredFee := oldTxFee + 1

// 5. Check if RBF is feasible
if minRequiredFee > maxAllowedFee {
    // Cannot proceed with RBF, user's MaxTxPrice is too low
    return
}

// 6. Smart fee selection
networkBasedFee := uint64(float64(networkFeeRate) * vbytes)

if networkBasedFee > oldTxFee && networkBasedFee <= maxAllowedFee {
    // Optimal: use current network fee rate
    actualFee = networkBasedFee
} else if networkBasedFee > maxAllowedFee {
    // Network congestion: use user's maximum allowed
    actualFee = maxAllowedFee
} else {
    // Network idle: only increase by 1 satoshi
    actualFee = minRequiredFee
}
```

### Fee Selection Priority

| Scenario | Selected Fee | Description |
|----------|--------------|-------------|
| `networkFee > oldTxFee && networkFee <= maxAllowed` | `networkFee` | Optimal: use current network rate |
| `networkFee > maxAllowed` | `maxAllowedFee` | Network congested but limited: use maximum |
| `networkFee <= oldTxFee` | `oldTxFee + 1` | Network idle: minimum increment |
| `minRequired > maxAllowed` | Abort RBF | Cannot proceed: MaxTxPrice too low |

## P2P Broadcast Mechanism

When the Proposer detects a UTXO conflict and completes cleanup, it needs to notify other nodes to synchronize state.

### Message Type

```go
type MsgSendOrderRbf struct {
    Txid      string `json:"txid"`       // Find order by txid
    OrderId   string `json:"order_id"`   // For verification
    OrderType string `json:"order_type"` // Order type
    Reason    string `json:"reason"`     // RBF reason
}
```

### Flow

```
Proposer Node                              Other Nodes
    |                                         |
    | 1. Detect UTXO conflict (-25)           |
    | 2. Check UTXO status via BTC RPC        |
    | 3. Execute CleanInitializedNeedRbfWithdrawByOrderId
    | 4. Broadcast MsgSendOrderRbf            |
    |---------------------------------------->|
    |                                         | 5. Receive message
    |                                         | 6. Find local order by txid
    |                                         | 7. Verify orderId matches
    |                                         | 8. Execute cleanup (assume UTXO spent)
```

### Non-Proposer Node Handling

```go
// Non-proposer nodes don't have BTC RPC access
// Trust proposer's cleanup result, assume all UTXOs are spent
_, cleanupErr := b.state.CleanInitializedNeedRbfWithdrawByOrderId(
    sendOrder.OrderId,
    func(utxoTxid string, outIndex int) (bool, error) {
        return true, nil // Assume spent
    })
```

## State Machine

### Safebox Order State Transitions

```
                    ┌─────────────┐
                    │   create    │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ received_ok │◄────────────────┐
                    └──────┬──────┘                 │
                           │                        │
                    ┌──────▼──────┐                 │
                    │    init     │                 │
                    └──────┬──────┘                 │
                           │                        │
                    ┌──────▼──────┐                 │
                    │   pending   │                 │
                    └──────┬──────┘                 │
                           │                        │
              ┌────────────┼────────────-┐          │
              │            │             │          │
       ┌──────▼──────┐ ┌───▼────┐ ┌────-─▼────-─┐   │
       │  confirmed  │ │ closed │ │UTXO conflict│───┘
       └─────────────┘ └────────┘ └──────────--─┘
                                   (reset task)
```

### Withdrawal Order State Transitions

```
                    ┌─────────────┐
                    │   create    │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ aggregating │◄──────────────------──┐
                    └──────┬──────┘                       │
                           │                              │
                    ┌──────▼──────┐                       │
                    │    init     │                       │
                    └──────┬──────┘                       │
                           │                              │
                    ┌──────▼──────┐                       │
                    │   pending   │                       │
                    └──────┬──────┘                       │
                           │                              │
       ┌───────────────────┼───────────────────-┐         │
       │                   │                    │         │
┌──────▼──────┐     ┌──────▼──────┐     ┌──────-▼──────┐  │
│  confirmed  │     │   closed    │     │ rbf-request  │  │
└─────────────┘     └─────────────┘     └──────-┬──────┘  │
                                                │         │
                                        ┌─────-─▼──────┐  │
                                        │  New order   │──┘
                                        │  aggregation │
                                        │(preserve Pid)│
                                        └─────────────-┘
```

## Key Code Locations

| Function | File Path |
|----------|-----------|
| UTXO conflict detection | `internal/wallet/withdraw_broadcast.go:315-358` |
| Cleanup logic | `internal/state/withdraw.go:815-943` |
| RBF signature initiation | `internal/wallet/withdraw.go:569-785` |
| Fee calculation | `internal/wallet/withdraw.go:717-766` |
| BLS signature aggregation | `internal/bls/handle_wallet.go:393-501` |
| Consensus layer submission | `internal/bls/handle_wallet.go:531-556` |
| P2P broadcast | `internal/wallet/withdraw_broadcast.go:349-365` |
| P2P receive handling | `internal/wallet/withdraw_broadcast.go:523-566` |

## Important Notes

### Strict Constraints for Withdrawal RBF

1. **Vout order must be consistent**: RBF transaction outputs must strictly follow the order of withdrawal IDs in the original ProcessWithdrawalV2
2. **Change output**: If change is less than dust, there may be no change output (vout count = withdrawalLen)
3. **Pid preservation**: RBF orders must preserve the original order's Pid; consensus layer associates original withdrawals through Pid
4. **Fee constraints**: New fee must be greater than old fee, and txPrice cannot exceed any withdrawal's MaxTxPrice

### Complete Rollback for Safebox

1. **Timestamp change**: Each aggregation uses current block time, causing timelock address changes
2. **Brand new transaction**: Equivalent to creating a transaction from scratch, no RBF constraints
3. **Simple recovery**: Just reset task status, next round will automatically re-aggregate

### Concurrency Safety

1. **Proposer uniqueness**: Only the current epoch's proposer can initiate RBF
2. **Signature state lock**: `sigMu` ensures only one signature process is running at a time
3. **Database transaction**: Cleanup operations are executed in a transaction to ensure atomicity
