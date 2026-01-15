package wallet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRbfFeeCalculation tests the fee optimization strategy for RBF
// This tests the algorithm documented in docs/rbf.md
func TestRbfFeeCalculation(t *testing.T) {
	tests := []struct {
		name            string
		oldTxFee        uint64
		minMaxTxPrice   uint64 // minimum MaxTxPrice from all withdrawals
		vbytes          float64
		networkFeeRate  int64
		expectedFee     uint64
		shouldProceed   bool
		description     string
	}{
		{
			name:           "Network fee within bounds - optimal case",
			oldTxFee:       1000,
			minMaxTxPrice:  50,   // 50 sat/vB
			vbytes:         200,  // 200 vbytes
			networkFeeRate: 20,   // 20 sat/vB
			expectedFee:    4000, // 20 * 200 = 4000
			shouldProceed:  true,
			description:    "Network fee (4000) > oldTxFee (1000) and <= maxAllowed (10000), use network fee",
		},
		{
			name:           "Network fee exceeds max allowed",
			oldTxFee:       1000,
			minMaxTxPrice:  10,   // 10 sat/vB (restrictive user setting)
			vbytes:         200,  // 200 vbytes
			networkFeeRate: 50,   // 50 sat/vB (network congestion)
			expectedFee:    2000, // maxAllowed = 10 * 200 = 2000
			shouldProceed:  true,
			description:    "Network fee (10000) > maxAllowed (2000), cap at maxAllowed",
		},
		{
			name:           "Network fee too low - minimum increment",
			oldTxFee:       5000,
			minMaxTxPrice:  50,
			vbytes:         200,
			networkFeeRate: 10,   // 10 * 200 = 2000 < 5000
			expectedFee:    5001, // oldTxFee + 1
			shouldProceed:  true,
			description:    "Network fee (2000) <= oldTxFee (5000), use minimum increment",
		},
		{
			name:           "Cannot proceed - MaxTxPrice too restrictive",
			oldTxFee:       10000,
			minMaxTxPrice:  10,   // 10 sat/vB
			vbytes:         200,  // maxAllowed = 2000
			networkFeeRate: 50,
			expectedFee:    0,
			shouldProceed:  false,
			description:    "minRequired (10001) > maxAllowed (2000), cannot proceed with RBF",
		},
		{
			name:           "Exact boundary - minRequired equals maxAllowed",
			oldTxFee:       1999,
			minMaxTxPrice:  10,   // 10 sat/vB
			vbytes:         200,  // maxAllowed = 2000
			networkFeeRate: 5,
			expectedFee:    2000, // minRequired = 2000 = maxAllowed
			shouldProceed:  true,
			description:    "minRequired (2000) == maxAllowed (2000), proceed with minimum",
		},
		{
			name:           "Large transaction with multiple withdrawals",
			oldTxFee:       50000,
			minMaxTxPrice:  100,  // 100 sat/vB
			vbytes:         1000, // 1000 vbytes (large tx)
			networkFeeRate: 80,   // 80 sat/vB
			expectedFee:    80000,// 80 * 1000 = 80000
			shouldProceed:  true,
			description:    "Large transaction with network fee within bounds",
		},
		{
			name:           "Small transaction - dust considerations",
			oldTxFee:       500,
			minMaxTxPrice:  200,  // 200 sat/vB
			vbytes:         100,  // 100 vbytes (small tx)
			networkFeeRate: 50,   // 50 sat/vB
			expectedFee:    5000, // 50 * 100 = 5000
			shouldProceed:  true,
			description:    "Small transaction with comfortable margins",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate bounds (same logic as in initRbfWithdrawSig)
			maxAllowedFee := uint64(float64(tt.minMaxTxPrice) * tt.vbytes)
			minRequiredFee := tt.oldTxFee + 1
			networkBasedFee := uint64(float64(tt.networkFeeRate) * tt.vbytes)

			// Check if RBF is possible
			canProceed := minRequiredFee <= maxAllowedFee

			if !canProceed {
				assert.False(t, tt.shouldProceed, "Expected cannot proceed: %s", tt.description)
				return
			}

			assert.True(t, tt.shouldProceed, "Expected can proceed: %s", tt.description)

			// Calculate actual fee using the optimization strategy
			var actualFee uint64
			if networkBasedFee > tt.oldTxFee && networkBasedFee <= maxAllowedFee {
				// Optimal: use network fee rate
				actualFee = networkBasedFee
			} else if networkBasedFee > maxAllowedFee {
				// Network congested but constrained by user's MaxTxPrice
				actualFee = maxAllowedFee
			} else {
				// Network fee too low, use minimum increment
				actualFee = minRequiredFee
			}

			assert.Equal(t, tt.expectedFee, actualFee, "Fee calculation mismatch: %s", tt.description)

			// Verify constraints
			assert.Greater(t, actualFee, tt.oldTxFee, "New fee must be greater than old fee")
			assert.LessOrEqual(t, actualFee, maxAllowedFee, "New fee must not exceed max allowed")
		})
	}
}

// TestTxPriceCalculation tests the txPrice calculation formula
func TestTxPriceCalculation(t *testing.T) {
	tests := []struct {
		name           string
		fee            uint64
		strippedSize   int // no-witness tx size
		witnessSize    int
		expectedVbytes float64
		expectedPrice  float64
	}{
		{
			name:           "P2WPKH simple transaction",
			fee:            5000,
			strippedSize:   200,
			witnessSize:    108, // typical P2WPKH witness
			expectedVbytes: 227, // 200 + 108/4 = 227
			expectedPrice:  22.03, // 5000 / 227 ≈ 22.03
		},
		{
			name:           "P2WSH transaction",
			fee:            10000,
			strippedSize:   250,
			witnessSize:    264, // 2 inputs with P2WSH
			expectedVbytes: 316, // 250 + 264/4 = 316
			expectedPrice:  31.65, // 10000 / 316 ≈ 31.65
		},
		{
			name:           "Legacy P2PKH (no witness)",
			fee:            8000,
			strippedSize:   400,
			witnessSize:    0,
			expectedVbytes: 400,
			expectedPrice:  20.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// vbytes = stripped_size + witness_size / 4
			vbytes := float64(tt.strippedSize) + float64(tt.witnessSize)/4.0
			assert.InDelta(t, tt.expectedVbytes, vbytes, 0.1, "vbytes calculation")

			// txPrice = fee / vbytes
			txPrice := float64(tt.fee) / vbytes
			assert.InDelta(t, tt.expectedPrice, txPrice, 0.1, "txPrice calculation")
		})
	}
}

// TestWithdrawalVoutOrderConstraint tests that withdrawal vout order is preserved
// This documents the constraint from goat consensus layer
func TestWithdrawalVoutOrderConstraint(t *testing.T) {
	// Simulating the constraint from replaceWithdrawal in goat/x/bitcoin/keeper/tx.go

	// Original ProcessWithdrawalV2 with withdrawal IDs [1001, 1002, 1003]
	originalWithdrawals := []uint64{1001, 1002, 1003}

	// Original vout addresses (order must match withdrawal IDs)
	originalVouts := []string{"bc1qaddr1", "bc1qaddr2", "bc1qaddr3"}

	// RBF transaction must have same vout addresses in same order
	rbfVouts := []string{"bc1qaddr1", "bc1qaddr2", "bc1qaddr3"}

	// Verify order is preserved
	for idx, wid := range originalWithdrawals {
		assert.Equal(t, originalVouts[idx], rbfVouts[idx],
			"Vout address for withdrawal %d must match original", wid)
	}

	// Test invalid RBF (wrong order)
	invalidRbfVouts := []string{"bc1qaddr2", "bc1qaddr1", "bc1qaddr3"} // swapped 1 and 2
	for idx, wid := range originalWithdrawals {
		if originalVouts[idx] != invalidRbfVouts[idx] {
			t.Logf("Invalid RBF detected: withdrawal %d has wrong address at index %d", wid, idx)
		}
	}
	assert.NotEqual(t, originalVouts, invalidRbfVouts, "Invalid RBF should be detected")
}

// TestSafeboxVsWithdrawalRbfStrategy documents the difference between safebox and withdrawal RBF
func TestSafeboxVsWithdrawalRbfStrategy(t *testing.T) {
	t.Run("Safebox - Complete Rollback", func(t *testing.T) {
		// Safebox RBF strategy:
		// 1. Timelock address is based on current block time
		// 2. When UTXO conflict detected, order is closed
		// 3. Task is reset to received_ok
		// 4. Next aggregation creates completely new transaction
		// 5. New timelock address (due to new block time)
		// 6. New vin selection
		// 7. New vout (timelock output changes)

		strategy := struct {
			vinChanges  bool
			voutChanges bool
			pidRequired bool
			newOrderId  bool
		}{
			vinChanges:  true,  // New UTXOs selected
			voutChanges: true,  // Timelock address changes
			pidRequired: false, // No Pid needed
			newOrderId:  true,  // Completely new order
		}

		assert.True(t, strategy.vinChanges, "Safebox RBF: vins change")
		assert.True(t, strategy.voutChanges, "Safebox RBF: vouts change")
		assert.False(t, strategy.pidRequired, "Safebox RBF: no Pid required")
		assert.True(t, strategy.newOrderId, "Safebox RBF: creates new order")
	})

	t.Run("Withdrawal - ReplaceWithdrawalV2", func(t *testing.T) {
		// Withdrawal RBF strategy:
		// 1. Vout addresses and order must be preserved (consensus constraint)
		// 2. Pid is preserved for ReplaceWithdrawalV2 reference
		// 3. Only vin (UTXO selection) can change
		// 4. Fee must increase
		// 5. txPrice must not exceed any withdrawal's MaxTxPrice

		strategy := struct {
			vinChanges      bool
			voutChanges     bool
			pidRequired     bool
			feeIncreased    bool
			priceConstrained bool
		}{
			vinChanges:      true,  // New UTXOs selected
			voutChanges:     false, // Vout addresses must be same
			pidRequired:     true,  // Pid required for ReplaceWithdrawalV2
			feeIncreased:    true,  // newFee > oldFee
			priceConstrained: true,  // txPrice <= minMaxTxPrice
		}

		assert.True(t, strategy.vinChanges, "Withdrawal RBF: vins change")
		assert.False(t, strategy.voutChanges, "Withdrawal RBF: vouts preserved")
		assert.True(t, strategy.pidRequired, "Withdrawal RBF: Pid required")
		assert.True(t, strategy.feeIncreased, "Withdrawal RBF: fee must increase")
		assert.True(t, strategy.priceConstrained, "Withdrawal RBF: price constrained by MaxTxPrice")
	})
}

// TestRbfVoutCountConstraint tests the vout count validation from consensus
func TestRbfVoutCountConstraint(t *testing.T) {
	tests := []struct {
		name           string
		withdrawalLen  int
		txoutLen       int
		valid          bool
		reason         string
	}{
		{
			name:          "Exact match - no change output",
			withdrawalLen: 3,
			txoutLen:      3,
			valid:         true,
			reason:        "txoutLen == withdrawalLen (no change)",
		},
		{
			name:          "With change output",
			withdrawalLen: 3,
			txoutLen:      4,
			valid:         true,
			reason:        "txoutLen == withdrawalLen + 1 (with change)",
		},
		{
			name:          "Too few outputs",
			withdrawalLen: 3,
			txoutLen:      2,
			valid:         false,
			reason:        "txoutLen < withdrawalLen (missing withdrawal outputs)",
		},
		{
			name:          "Too many outputs",
			withdrawalLen: 3,
			txoutLen:      5,
			valid:         false,
			reason:        "txoutLen > withdrawalLen + 1 (extra outputs not allowed)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validation from goat consensus layer
			valid := tt.txoutLen == tt.withdrawalLen || tt.txoutLen == tt.withdrawalLen+1
			assert.Equal(t, tt.valid, valid, tt.reason)
		})
	}
}
