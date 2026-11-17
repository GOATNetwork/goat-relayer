package state

import (
	"testing"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *gorm.DB {
	testDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)

	// Auto migrate all models
	err = testDB.AutoMigrate(
		&db.SendOrder{},
		&db.Vin{},
		&db.Vout{},
		&db.Utxo{},
		&db.Withdraw{},
		&db.SafeboxTask{},
	)
	require.NoError(t, err)

	return testDB
}

// TestRbfWithdrawalFlow tests the RBF flow for withdrawal orders
func TestRbfWithdrawalFlow(t *testing.T) {
	testDB := setupTestDB(t)

	// Setup: Create a withdrawal order with UTXOs
	orderId := "test-withdrawal-order-001"
	pid := uint64(12345)

	// Create send order
	sendOrder := &db.SendOrder{
		OrderId:     orderId,
		Proposer:    "goat1proposer",
		Pid:         pid,
		Amount:      1000000, // 0.01 BTC
		TxPrice:     100,
		Status:      db.ORDER_STATUS_PENDING,
		OrderType:   db.ORDER_TYPE_WITHDRAWAL,
		BtcBlock:    0,
		Txid:        "original-txid-abc123",
		NoWitnessTx: []byte{0x01, 0x02, 0x03},
		TxFee:       5000,
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, testDB.Create(sendOrder).Error)

	// Create UTXOs (simulating spent and unspent)
	utxos := []*db.Utxo{
		{
			Txid:         "utxo-txid-001",
			OutIndex:     0,
			Amount:       500000,
			Receiver:     "bc1qtest1",
			ReceiverType: "P2WPKH",
			Status:       db.UTXO_STATUS_PENDING,
			UpdatedAt:    time.Now(),
		},
		{
			Txid:         "utxo-txid-002",
			OutIndex:     1,
			Amount:       600000,
			Receiver:     "bc1qtest2",
			ReceiverType: "P2WPKH",
			Status:       db.UTXO_STATUS_PENDING,
			UpdatedAt:    time.Now(),
		},
	}
	for _, utxo := range utxos {
		require.NoError(t, testDB.Create(utxo).Error)
	}

	// Create Vins linking order to UTXOs
	vins := []*db.Vin{
		{
			OrderId:   orderId,
			BtcHeight: 100,
			Txid:      "utxo-txid-001",
			OutIndex:  0,
			Status:    db.ORDER_STATUS_PENDING,
			UpdatedAt: time.Now(),
		},
		{
			OrderId:   orderId,
			BtcHeight: 100,
			Txid:      "utxo-txid-002",
			OutIndex:  1,
			Status:    db.ORDER_STATUS_PENDING,
			UpdatedAt: time.Now(),
		},
	}
	for _, vin := range vins {
		require.NoError(t, testDB.Create(vin).Error)
	}

	// Create Vouts
	vouts := []*db.Vout{
		{
			OrderId:    orderId,
			BtcHeight:  0,
			Txid:       "original-txid-abc123",
			OutIndex:   0,
			WithdrawId: "1001",
			Amount:     450000,
			Receiver:   "bc1qwithdraw1",
			Status:     db.ORDER_STATUS_PENDING,
			UpdatedAt:  time.Now(),
		},
		{
			OrderId:    orderId,
			BtcHeight:  0,
			Txid:       "original-txid-abc123",
			OutIndex:   1,
			WithdrawId: "1002",
			Amount:     450000,
			Receiver:   "bc1qwithdraw2",
			Status:     db.ORDER_STATUS_PENDING,
			UpdatedAt:  time.Now(),
		},
	}
	for _, vout := range vouts {
		require.NoError(t, testDB.Create(vout).Error)
	}

	// Create Withdraws
	withdraws := []*db.Withdraw{
		{
			RequestId: 1001,
			GoatBlock: 100,
			Amount:    500000,
			TxPrice:   100,
			From:      "0xuser1",
			To:        "bc1qwithdraw1",
			Status:    db.WITHDRAW_STATUS_PENDING,
			OrderId:   orderId,
			Txid:      "original-txid-abc123",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			RequestId: 1002,
			GoatBlock: 100,
			Amount:    500000,
			TxPrice:   100,
			From:      "0xuser2",
			To:        "bc1qwithdraw2",
			Status:    db.WITHDRAW_STATUS_PENDING,
			OrderId:   orderId,
			Txid:      "original-txid-abc123",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
	for _, withdraw := range withdraws {
		require.NoError(t, testDB.Create(withdraw).Error)
	}

	// Simulate UTXO spent check callback
	// First UTXO is spent, second is not spent
	spentUtxos := map[string]bool{
		"utxo-txid-001:0": true,  // spent
		"utxo-txid-002:1": false, // not spent
	}
	checkUtxoSpent := func(txid string, outIndex int) (bool, error) {
		key := txid + ":" + string(rune('0'+outIndex))
		return spentUtxos[key], nil
	}

	// Create mock State with test DB
	mockState := newStateForTest(testDB)

	// Execute cleanup
	orderType, err := mockState.CleanInitializedNeedRbfWithdrawByOrderId(orderId, checkUtxoSpent)
	require.NoError(t, err)
	assert.Equal(t, db.ORDER_TYPE_WITHDRAWAL, orderType)

	// Verify results

	// 1. Order should be marked as RBF_REQUEST
	var updatedOrder db.SendOrder
	require.NoError(t, testDB.Where("order_id = ?", orderId).First(&updatedOrder).Error)
	assert.Equal(t, db.ORDER_STATUS_RBF_REQUEST, updatedOrder.Status)
	assert.Equal(t, pid, updatedOrder.Pid) // Pid should be preserved

	// 2. First UTXO should be marked as spent
	var utxo1 db.Utxo
	require.NoError(t, testDB.Where("txid = ? AND out_index = ?", "utxo-txid-001", 0).First(&utxo1).Error)
	assert.Equal(t, db.UTXO_STATUS_SPENT, utxo1.Status)

	// 3. Second UTXO should be restored to processed
	var utxo2 db.Utxo
	require.NoError(t, testDB.Where("txid = ? AND out_index = ?", "utxo-txid-002", 1).First(&utxo2).Error)
	assert.Equal(t, db.UTXO_STATUS_PROCESSED, utxo2.Status)

	// 4. Vins and Vouts should be closed
	var vinCount int64
	testDB.Model(&db.Vin{}).Where("order_id = ? AND status = ?", orderId, db.ORDER_STATUS_CLOSED).Count(&vinCount)
	assert.Equal(t, int64(2), vinCount)

	var voutCount int64
	testDB.Model(&db.Vout{}).Where("order_id = ? AND status = ?", orderId, db.ORDER_STATUS_CLOSED).Count(&voutCount)
	assert.Equal(t, int64(2), voutCount)

	// 5. Withdraws should be restored to aggregating
	var withdrawCount int64
	testDB.Model(&db.Withdraw{}).Where("order_id = ? AND status = ?", orderId, db.WITHDRAW_STATUS_AGGREGATING).Count(&withdrawCount)
	assert.Equal(t, int64(2), withdrawCount)
}

// TestRbfSafeboxFlow tests the RBF flow for safebox orders
func TestRbfSafeboxFlow(t *testing.T) {
	testDB := setupTestDB(t)

	// Setup: Create a safebox order with UTXOs
	orderId := "test-safebox-order-001"

	// Create send order
	sendOrder := &db.SendOrder{
		OrderId:     orderId,
		Proposer:    "goat1proposer",
		Pid:         0, // Safebox orders don't have Pid
		Amount:      1000000,
		TxPrice:     100,
		Status:      db.ORDER_STATUS_PENDING,
		OrderType:   db.ORDER_TYPE_SAFEBOX,
		BtcBlock:    0,
		Txid:        "safebox-txid-abc123",
		NoWitnessTx: []byte{0x01, 0x02, 0x03},
		TxFee:       5000,
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, testDB.Create(sendOrder).Error)

	// Create UTXOs
	utxos := []*db.Utxo{
		{
			Txid:         "utxo-txid-001",
			OutIndex:     0,
			Amount:       500000,
			Receiver:     "bc1qtest1",
			ReceiverType: "P2WPKH",
			Status:       db.UTXO_STATUS_PENDING,
			UpdatedAt:    time.Now(),
		},
		{
			Txid:         "utxo-txid-002",
			OutIndex:     1,
			Amount:       600000,
			Receiver:     "bc1qtest2",
			ReceiverType: "P2WPKH",
			Status:       db.UTXO_STATUS_PENDING,
			UpdatedAt:    time.Now(),
		},
	}
	for _, utxo := range utxos {
		require.NoError(t, testDB.Create(utxo).Error)
	}

	// Create Vins
	vins := []*db.Vin{
		{
			OrderId:   orderId,
			BtcHeight: 100,
			Txid:      "utxo-txid-001",
			OutIndex:  0,
			Status:    db.ORDER_STATUS_PENDING,
			UpdatedAt: time.Now(),
		},
		{
			OrderId:   orderId,
			BtcHeight: 100,
			Txid:      "utxo-txid-002",
			OutIndex:  1,
			Status:    db.ORDER_STATUS_PENDING,
			UpdatedAt: time.Now(),
		},
	}
	for _, vin := range vins {
		require.NoError(t, testDB.Create(vin).Error)
	}

	// Create Vouts (safebox has timelock output)
	vouts := []*db.Vout{
		{
			OrderId:   orderId,
			BtcHeight: 0,
			Txid:      "safebox-txid-abc123",
			OutIndex:  0,
			Amount:    995000,
			Receiver:  "bc1qtimelock_address",
			Status:    db.ORDER_STATUS_PENDING,
			UpdatedAt: time.Now(),
		},
	}
	for _, vout := range vouts {
		require.NoError(t, testDB.Create(vout).Error)
	}

	// Create SafeboxTask
	safeboxTask := &db.SafeboxTask{
		TaskId:          1001,
		PartnerId:       "partner-001",
		DepositAddress:  "bc1qdeposit",
		Amount:          1000000,
		TimelockAddress: "bc1qtimelock_address",
		BtcAddress:      "bc1qbtc",
		Status:          db.TASK_STATUS_INIT,
		OrderId:         orderId,
		UpdatedAt:       time.Now(),
	}
	require.NoError(t, testDB.Create(safeboxTask).Error)

	// All UTXOs are spent
	checkUtxoSpent := func(txid string, outIndex int) (bool, error) {
		return true, nil
	}

	// Create mock State with test DB
	mockState := newStateForTest(testDB)

	// Execute cleanup
	orderType, err := mockState.CleanInitializedNeedRbfWithdrawByOrderId(orderId, checkUtxoSpent)
	require.NoError(t, err)
	assert.Equal(t, db.ORDER_TYPE_SAFEBOX, orderType)

	// Verify results

	// 1. Order should be closed (not RBF_REQUEST)
	var updatedOrder db.SendOrder
	require.NoError(t, testDB.Where("order_id = ?", orderId).First(&updatedOrder).Error)
	assert.Equal(t, db.ORDER_STATUS_CLOSED, updatedOrder.Status)

	// 2. UTXOs should be marked as spent
	var utxo1 db.Utxo
	require.NoError(t, testDB.Where("txid = ? AND out_index = ?", "utxo-txid-001", 0).First(&utxo1).Error)
	assert.Equal(t, db.UTXO_STATUS_SPENT, utxo1.Status)

	var utxo2 db.Utxo
	require.NoError(t, testDB.Where("txid = ? AND out_index = ?", "utxo-txid-002", 1).First(&utxo2).Error)
	assert.Equal(t, db.UTXO_STATUS_SPENT, utxo2.Status)

	// 3. Vins and Vouts should be closed
	var vinCount int64
	testDB.Model(&db.Vin{}).Where("order_id = ? AND status = ?", orderId, db.ORDER_STATUS_CLOSED).Count(&vinCount)
	assert.Equal(t, int64(2), vinCount)

	// 4. SafeboxTask should be reset to received_ok
	var updatedTask db.SafeboxTask
	require.NoError(t, testDB.Where("order_id = ?", orderId).First(&updatedTask).Error)
	assert.Equal(t, db.TASK_STATUS_RECEIVED_OK, updatedTask.Status)
}

// TestRbfWithdrawalPreservesVoutOrder tests that withdrawal RBF preserves vout order
func TestRbfWithdrawalPreservesVoutOrder(t *testing.T) {
	testDB := setupTestDB(t)

	orderId := "test-withdrawal-order-002"
	pid := uint64(99999)

	// Create order with specific withdrawal order
	sendOrder := &db.SendOrder{
		OrderId:     orderId,
		Proposer:    "goat1proposer",
		Pid:         pid,
		Amount:      3000000, // 0.03 BTC total
		TxPrice:     50,
		Status:      db.ORDER_STATUS_PENDING,
		OrderType:   db.ORDER_TYPE_WITHDRAWAL,
		Txid:        "original-txid-xyz789",
		NoWitnessTx: []byte{0x01, 0x02, 0x03},
		TxFee:       10000,
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, testDB.Create(sendOrder).Error)

	// Create withdrawals with specific order (IDs: 2001, 2002, 2003)
	// This order must be preserved in RBF
	withdraws := []*db.Withdraw{
		{RequestId: 2001, Amount: 1000000, To: "bc1qaddr1", Status: db.WITHDRAW_STATUS_PENDING, OrderId: orderId, TxPrice: 50, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{RequestId: 2002, Amount: 1000000, To: "bc1qaddr2", Status: db.WITHDRAW_STATUS_PENDING, OrderId: orderId, TxPrice: 60, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{RequestId: 2003, Amount: 1000000, To: "bc1qaddr3", Status: db.WITHDRAW_STATUS_PENDING, OrderId: orderId, TxPrice: 70, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}
	for _, w := range withdraws {
		require.NoError(t, testDB.Create(w).Error)
	}

	// Create UTXOs
	utxo := &db.Utxo{
		Txid:         "utxo-txid-large",
		OutIndex:     0,
		Amount:       3500000,
		Receiver:     "bc1qsystem",
		ReceiverType: "P2WPKH",
		Status:       db.UTXO_STATUS_PENDING,
		UpdatedAt:    time.Now(),
	}
	require.NoError(t, testDB.Create(utxo).Error)

	// Create Vin
	vin := &db.Vin{
		OrderId:   orderId,
		Txid:      "utxo-txid-large",
		OutIndex:  0,
		Status:    db.ORDER_STATUS_PENDING,
		UpdatedAt: time.Now(),
	}
	require.NoError(t, testDB.Create(vin).Error)

	// Create Vouts (order matches withdrawal IDs)
	vouts := []*db.Vout{
		{OrderId: orderId, Txid: "original-txid-xyz789", OutIndex: 0, WithdrawId: "2001", Amount: 990000, Receiver: "bc1qaddr1", Status: db.ORDER_STATUS_PENDING, UpdatedAt: time.Now()},
		{OrderId: orderId, Txid: "original-txid-xyz789", OutIndex: 1, WithdrawId: "2002", Amount: 990000, Receiver: "bc1qaddr2", Status: db.ORDER_STATUS_PENDING, UpdatedAt: time.Now()},
		{OrderId: orderId, Txid: "original-txid-xyz789", OutIndex: 2, WithdrawId: "2003", Amount: 990000, Receiver: "bc1qaddr3", Status: db.ORDER_STATUS_PENDING, UpdatedAt: time.Now()},
		{OrderId: orderId, Txid: "original-txid-xyz789", OutIndex: 3, WithdrawId: "", Amount: 500000, Receiver: "bc1qchange", Status: db.ORDER_STATUS_PENDING, UpdatedAt: time.Now()}, // change output
	}
	for _, vout := range vouts {
		require.NoError(t, testDB.Create(vout).Error)
	}

	// Create mock State with test DB
	mockState := newStateForTest(testDB)

	// Execute cleanup
	checkUtxoSpent := func(txid string, outIndex int) (bool, error) {
		return true, nil // All spent
	}

	orderType, err := mockState.CleanInitializedNeedRbfWithdrawByOrderId(orderId, checkUtxoSpent)
	require.NoError(t, err)
	assert.Equal(t, db.ORDER_TYPE_WITHDRAWAL, orderType)

	// Verify: Withdrawals should be in aggregating status (preserving original order)
	var restoredWithdraws []db.Withdraw
	require.NoError(t, testDB.Where("order_id = ?", orderId).Order("request_id").Find(&restoredWithdraws).Error)
	assert.Len(t, restoredWithdraws, 3)

	// Verify order is preserved (sorted by request_id)
	assert.Equal(t, uint64(2001), restoredWithdraws[0].RequestId)
	assert.Equal(t, uint64(2002), restoredWithdraws[1].RequestId)
	assert.Equal(t, uint64(2003), restoredWithdraws[2].RequestId)

	// All should be in aggregating status for re-processing
	for _, w := range restoredWithdraws {
		assert.Equal(t, db.WITHDRAW_STATUS_AGGREGATING, w.Status)
	}

	// Verify Pid is preserved
	var updatedOrder db.SendOrder
	require.NoError(t, testDB.Where("order_id = ?", orderId).First(&updatedOrder).Error)
	assert.Equal(t, pid, updatedOrder.Pid)
}

// TestRbfFeeCalculation tests the fee optimization strategy
func TestRbfFeeCalculation(t *testing.T) {
	tests := []struct {
		name            string
		oldTxFee        uint64
		minMaxTxPrice   uint64
		vbytes          float64
		networkFeeRate  int64
		expectedFee     uint64
		shouldProceed   bool
	}{
		{
			name:           "Network fee within bounds",
			oldTxFee:       1000,
			minMaxTxPrice:  50,   // 50 sat/vB
			vbytes:         200,  // 200 vbytes
			networkFeeRate: 20,   // 20 sat/vB
			expectedFee:    4000, // 20 * 200 = 4000
			shouldProceed:  true,
		},
		{
			name:           "Network fee exceeds max, use max",
			oldTxFee:       1000,
			minMaxTxPrice:  10,   // 10 sat/vB
			vbytes:         200,  // 200 vbytes
			networkFeeRate: 50,   // 50 sat/vB (too high)
			expectedFee:    2000, // maxAllowed = 10 * 200 = 2000
			shouldProceed:  true,
		},
		{
			name:           "Network fee too low, use minimum increment",
			oldTxFee:       5000,
			minMaxTxPrice:  50,
			vbytes:         200,
			networkFeeRate: 10,   // 10 * 200 = 2000 < 5000
			expectedFee:    5001, // oldTxFee + 1
			shouldProceed:  true,
		},
		{
			name:           "Cannot proceed - max allowed less than min required",
			oldTxFee:       10000,
			minMaxTxPrice:  10,  // 10 sat/vB
			vbytes:         200, // maxAllowed = 2000
			networkFeeRate: 50,
			expectedFee:    0,
			shouldProceed:  false, // 10001 > 2000
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maxAllowedFee := uint64(float64(tt.minMaxTxPrice) * tt.vbytes)
			minRequiredFee := tt.oldTxFee + 1
			networkBasedFee := uint64(float64(tt.networkFeeRate) * tt.vbytes)

			// Check if RBF is possible
			canProceed := minRequiredFee <= maxAllowedFee

			if !canProceed {
				assert.False(t, tt.shouldProceed, "Expected cannot proceed")
				return
			}

			assert.True(t, tt.shouldProceed, "Expected can proceed")

			// Calculate actual fee
			var actualFee uint64
			if networkBasedFee > tt.oldTxFee && networkBasedFee <= maxAllowedFee {
				actualFee = networkBasedFee
			} else if networkBasedFee > maxAllowedFee {
				actualFee = maxAllowedFee
			} else {
				actualFee = minRequiredFee
			}

			assert.Equal(t, tt.expectedFee, actualFee)
		})
	}
}

// TestConsolidationOrderCleanup tests that consolidation orders are simply closed
func TestConsolidationOrderCleanup(t *testing.T) {
	testDB := setupTestDB(t)

	orderId := "test-consolidation-order-001"

	sendOrder := &db.SendOrder{
		OrderId:     orderId,
		Proposer:    "goat1proposer",
		Pid:         0,
		Amount:      5000000,
		TxPrice:     20,
		Status:      db.ORDER_STATUS_PENDING,
		OrderType:   db.ORDER_TYPE_CONSOLIDATION,
		Txid:        "consolidation-txid-abc",
		NoWitnessTx: []byte{0x01, 0x02},
		TxFee:       2000,
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, testDB.Create(sendOrder).Error)

	// Create UTXOs and Vins
	for i := 0; i < 5; i++ {
		utxo := &db.Utxo{
			Txid:         "consolidate-utxo-" + string(rune('0'+i)),
			OutIndex:     0,
			Amount:       1000000,
			Receiver:     "bc1qsystem",
			ReceiverType: "P2WPKH",
			Status:       db.UTXO_STATUS_PENDING,
			UpdatedAt:    time.Now(),
		}
		require.NoError(t, testDB.Create(utxo).Error)

		vin := &db.Vin{
			OrderId:   orderId,
			Txid:      "consolidate-utxo-" + string(rune('0'+i)),
			OutIndex:  0,
			Status:    db.ORDER_STATUS_PENDING,
			UpdatedAt: time.Now(),
		}
		require.NoError(t, testDB.Create(vin).Error)
	}

	// Create mock State with test DB
	mockState := newStateForTest(testDB)

	checkUtxoSpent := func(txid string, outIndex int) (bool, error) {
		return true, nil
	}

	orderType, err := mockState.CleanInitializedNeedRbfWithdrawByOrderId(orderId, checkUtxoSpent)
	require.NoError(t, err)
	assert.Equal(t, db.ORDER_TYPE_CONSOLIDATION, orderType)

	// Consolidation orders should simply be closed
	var updatedOrder db.SendOrder
	require.NoError(t, testDB.Where("order_id = ?", orderId).First(&updatedOrder).Error)
	assert.Equal(t, db.ORDER_STATUS_CLOSED, updatedOrder.Status)
}
