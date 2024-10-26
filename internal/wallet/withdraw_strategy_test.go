package wallet_test

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/types"
	"github.com/goatnetwork/goat-relayer/internal/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test ConsolidateSmallUTXOs function
func TestConsolidateSmallUTXOs(t *testing.T) {
	config.AppConfig.BTCMaxNetworkFee = 200
	// mock UTXOs for testing
	utxos := []*db.Utxo{
		{Amount: 20000000, ReceiverType: types.WALLET_TYPE_P2PKH},
		{Amount: 15000000, ReceiverType: types.WALLET_TYPE_P2WPKH},
		{Amount: 10000000, ReceiverType: types.WALLET_TYPE_P2WPKH},
		{Amount: 10000000, ReceiverType: types.WALLET_TYPE_P2WPKH},
		{Amount: 10000000, ReceiverType: types.WALLET_TYPE_P2WPKH},
		{Amount: 10000000, ReceiverType: types.WALLET_TYPE_P2WPKH},
		{Amount: 10000000, ReceiverType: types.WALLET_TYPE_P2WPKH},
		{Amount: 10000000, ReceiverType: types.WALLET_TYPE_P2WPKH},
		{Amount: 10000000, ReceiverType: types.WALLET_TYPE_P2WPKH},
		{Amount: 15000000, ReceiverType: types.WALLET_TYPE_P2WSH},
		{Amount: 5000000, ReceiverType: types.WALLET_TYPE_P2PKH},
	}

	// when network fee is too high
	selectedUtxos, totalAmount, finalAmount, err := wallet.ConsolidateSmallUTXOs(utxos, 300, 10000000, 10, 10)
	assert.Error(t, err)
	assert.EqualError(t, err, "network fee is too high, cannot consolidate")
	assert.Nil(t, selectedUtxos)
	assert.Equal(t, int64(0), totalAmount)
	assert.Equal(t, int64(0), finalAmount)

	// when there are not enough UTXOs to consolidate
	selectedUtxos, totalAmount, finalAmount, err = wallet.ConsolidateSmallUTXOs(utxos, 100, 10000000, 10, 10)
	assert.Error(t, err)
	assert.EqualError(t, err, "not enough small utxos to consolidate")
	assert.Nil(t, selectedUtxos)
	assert.Equal(t, int64(0), totalAmount)
	assert.Equal(t, int64(0), finalAmount)

	// valid consolidation
	selectedUtxos, totalAmount, finalAmount, err = wallet.ConsolidateSmallUTXOs(utxos, 100, 20000000, 10, 10)
	assert.NoError(t, err)
	assert.NotNil(t, selectedUtxos)
	assert.Greater(t, totalAmount, int64(0))
	assert.Greater(t, finalAmount, int64(0))
}

// Test SelectOptimalUTXOs function
func TestSelectOptimalUTXOs(t *testing.T) {
	// mock UTXOs for testing
	utxos := []*db.Utxo{
		{Amount: 50000000, ReceiverType: types.WALLET_TYPE_P2PKH},
		{Amount: 30000000, ReceiverType: types.WALLET_TYPE_P2WPKH},
		{Amount: 20000000, ReceiverType: types.WALLET_TYPE_P2WSH},
		{Amount: 15000000, ReceiverType: types.WALLET_TYPE_P2PKH},
	}

	// valid selection of UTXOs
	selectedUtxos, totalSelectedAmount, withdrawAmount, changeAmount, estimatedFee, err := wallet.SelectOptimalUTXOs(utxos, []string{types.WALLET_TYPE_P2WPKH}, 40000000, 100, 1)
	assert.NoError(t, err)
	assert.NotNil(t, selectedUtxos)
	assert.Greater(t, totalSelectedAmount, int64(0))
	assert.Equal(t, int64(40000000), withdrawAmount)
	assert.Greater(t, changeAmount, int64(0))
	assert.Greater(t, estimatedFee, int64(0))

	// when not enough UTXOs
	_, _, _, _, estimatedFee, err = wallet.SelectOptimalUTXOs(utxos, []string{types.WALLET_TYPE_P2WPKH}, 150000000, 100, 1)
	assert.Error(t, err)
	assert.EqualError(t, err, fmt.Sprintf("not enough utxos to satisfy the withdrawal amount and network fee, withdraw amount: 150000000, selected amount: 115000000, estimated fee: %d", estimatedFee))
}

// Test SelectWithdrawals function
func TestSelectWithdrawals(t *testing.T) {
	config.AppConfig.BTCMaxNetworkFee = 500
	// mock Withdrawals for testing
	withdrawals := []*db.Withdraw{
		{Amount: 70000000, TxPrice: 300, CreatedAt: time.Now().Add(-time.Minute * 20)},
		{Amount: 50000000, TxPrice: 200, CreatedAt: time.Now().Add(-time.Minute * 20)},
		{Amount: 30000000, TxPrice: 100, CreatedAt: time.Now().Add(-time.Minute * 20)},
		{Amount: 15000000, TxPrice: 50, CreatedAt: time.Now().Add(-time.Minute * 20)},
	}

	// valid withdrawal selection
	selectedWithdrawals, receiverTypes, withdrawAmount, minTxFee, err := wallet.SelectWithdrawals(withdrawals, types.BtcNetworkFee{
		FastestFee:  100,
		HalfHourFee: 50,
		HourFee:     20,
	}, 2, 150, types.GetBTCNetwork("regtest"))
	t.Logf("SelectWithdrawals returns selectedWithdrawals len %d, receiverTypes %v, withdrawAmount %d, minTxFee %d, err %v", len(selectedWithdrawals), receiverTypes, withdrawAmount, minTxFee, err)
	assert.NoError(t, err)
	assert.NotNil(t, selectedWithdrawals)
	assert.Greater(t, withdrawAmount, int64(0))
	assert.Greater(t, minTxFee, int64(0))

	// when network fee is too high
	_, _, _, _, err = wallet.SelectWithdrawals(withdrawals, types.BtcNetworkFee{
		FastestFee:  600,
		HalfHourFee: 300,
		HourFee:     100,
	}, 2, 150, types.GetBTCNetwork("regtest"))
	assert.Error(t, err)
	assert.EqualError(t, err, "network fee too high, no withdrawals allowed")
}

// Test CreateRawTransaction function
func TestCreateRawTransaction(t *testing.T) {
	// mock UTXOs for testing
	utxos := []*db.Utxo{
		{Txid: "a3e0d1c3ff01", OutIndex: 0, Amount: 50000000, ReceiverType: types.WALLET_TYPE_P2PKH, Sender: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
		{Txid: "b4f1e2d4ff02", OutIndex: 1, Amount: 30000000, ReceiverType: types.WALLET_TYPE_P2WPKH, Sender: "bc1q254g9ax097y04erwjesrrce8nv3t7k0ajwylwu"},
	}

	// mock Withdrawals for testing
	withdrawals := []*db.Withdraw{
		{Amount: 20000000, To: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", TxPrice: 20, ID: 1},
		{Amount: 10000000, To: "bc1q254g9ax097y04erwjesrrce8nv3t7k0ajwylwu", TxPrice: 10, ID: 2},
	}

	// bitcoin mainnet params
	net := &chaincfg.MainNetParams

	// valid transaction creation
	tx, dustWithdraw, err := wallet.CreateRawTransaction(utxos, withdrawals, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 5000000, 1000, 10, net)
	assert.NoError(t, err)
	assert.NotNil(t, tx)
	assert.Equal(t, uint(0), dustWithdraw)

	// validate transaction inputs and outputs
	assert.Equal(t, 2, len(tx.TxIn))  // 2 inputs
	assert.Equal(t, 3, len(tx.TxOut)) // 2 withdrawals + 1 change

	// check if inputs are added correctly
	for i, utxo := range utxos {
		expectedHash, _ := chainhash.NewHashFromStr(utxo.Txid)
		assert.Equal(t, expectedHash, &tx.TxIn[i].PreviousOutPoint.Hash)
		assert.Equal(t, uint32(utxo.OutIndex), tx.TxIn[i].PreviousOutPoint.Index)
	}

	// check if outputs are added correctly
	for i, withdrawal := range withdrawals {
		addr, err := btcutil.DecodeAddress(withdrawal.To, net)
		assert.NoError(t, err)
		expectedScript, err := txscript.PayToAddrScript(addr)
		assert.NoError(t, err)
		assert.Equal(t, expectedScript, tx.TxOut[i].PkScript)
		assert.Equal(t, int64(withdrawal.Amount)-1000/3, tx.TxOut[i].Value) // minus fee
	}

	// when withdrawal amount is too small (dust)
	withdrawals[0].Amount = 500 // less than dust limit
	_, dustWithdraw, err = wallet.CreateRawTransaction(utxos, withdrawals, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 5000000, 1000, 10, net)
	assert.Error(t, err)
	assert.Equal(t, uint(1), dustWithdraw) // the ID of the withdrawal with the small amount
	assert.EqualError(t, err, fmt.Sprintf("withdrawal amount too small after fee deduction: %d", withdrawals[0].Amount-1000/3))
}

// Test SignTransactionByPrivKey function
func TestSpentP2wpkh(t *testing.T) {
	privKeyHex := "e9ccd0ec6bb77c263dc46c0f81962c0b378a67befe089e90ef81e96a4a4c5bc5"
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	require.NoError(t, err)
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	nowitnessHex := "01000000029C1E3B925508BFDA1EA5420062310BC05194174DD88A2C0A081E4C3F48DAE4FE0000000000FFFFFFFFB085207198C6D04687B8A1446DE9CC22DCC74F320B0AFA60E8A1415BC1FF82CD0000000000FFFFFFFF021F47980000000000160014B4278200CDA9E9E4F4FCEB6DFC4A9AED115A0B609FEA7C29010000001600149759ED6AAE6ADE43AE6628A943A39974CD21C5DF00000000"
	nowitnessBytes, err := hex.DecodeString(nowitnessHex)
	require.NoError(t, err)

	tx, err := types.DeserializeTransaction(nowitnessBytes)
	require.NoError(t, err)

	utxo1 := &db.Utxo{
		ReceiverType: "P2WPKH",
		Receiver:     "bcrt1qjav7664wdt0y8tnx9z558guewnxjr3wllz2s9u",
		Amount:       5000000000,
	}
	utxo2 := &db.Utxo{
		ReceiverType: "P2WPKH",
		Receiver:     "bcrt1qjav7664wdt0y8tnx9z558guewnxjr3wllz2s9u",
		Amount:       1000000,
	}

	// sign transaction
	err = wallet.SignTransactionByPrivKey(privKey, tx, []*db.Utxo{utxo1, utxo2}, &chaincfg.RegressionNetParams)
	require.NoError(t, err)
}

func TestSpentP2wsh(t *testing.T) {
	privKeyHex := "e9ccd0ec6bb77c263dc46c0f81962c0b378a67befe089e90ef81e96a4a4c5bc5"
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	require.NoError(t, err)
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	noWitnessHex := "01000000014add7aad09a9584b477124474ff29e81b00fda7f43176278e4028e7dac7e74a20000000000ffffffff02c84b000000000000220020adee3cac019d80f80c5cbb368948f89bb90b93e01cb83b30b5f69b3f98fdebd5c84b000000000000160014d210b97931bebefa754ade28ead2c70bee9f1f2700000000"
	noWitnessBytes, err := hex.DecodeString(noWitnessHex)
	require.NoError(t, err)

	evmAddress := "29cF29d4b2CD6Db07f6db43243e8E43fE3DC468e"
	evmAddressBytes, err := hex.DecodeString(evmAddress)
	require.NoError(t, err)

	tx, err := types.DeserializeTransaction(noWitnessBytes)
	require.NoError(t, err)

	subScript, err := txscript.NewScriptBuilder().
		AddData(evmAddressBytes).
		AddOp(txscript.OP_DROP).
		AddData(privKey.PubKey().SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).Script()
	require.NoError(t, err)

	utxo := &db.Utxo{
		ReceiverType: "P2WSH",
		Receiver:     "tb1q4hhretqpnkq0srzuhvmgjj8cnwushylqrjurkv9476dnlx8aa02s8r565l",
		SubScript:    subScript,
		Amount:       100000,
	}

	// sign transaction
	err = wallet.SignTransactionByPrivKey(privKey, tx, []*db.Utxo{utxo}, &chaincfg.TestNet3Params)
	require.NoError(t, err)
	txBytes, err := types.SerializeTransaction(tx)
	assert.NoError(t, err)
	t.Logf("txBytes: %s", hex.EncodeToString(txBytes))
}

// Test GenerateRawMeessageToFireblocks function
func TestGenerateRawMeessageToFireblocks(t *testing.T) {
	nowitnessHex := "01000000029C1E3B925508BFDA1EA5420062310BC05194174DD88A2C0A081E4C3F48DAE4FE0000000000FFFFFFFFB085207198C6D04687B8A1446DE9CC22DCC74F320B0AFA60E8A1415BC1FF82CD0000000000FFFFFFFF021F47980000000000160014B4278200CDA9E9E4F4FCEB6DFC4A9AED115A0B609FEA7C29010000001600149759ED6AAE6ADE43AE6628A943A39974CD21C5DF00000000"
	nowitnessBytes, err := hex.DecodeString(nowitnessHex)
	require.NoError(t, err)

	tx, err := types.DeserializeTransaction(nowitnessBytes)
	require.NoError(t, err)

	utxo1 := &db.Utxo{
		ReceiverType: "P2WPKH",
		Receiver:     "bcrt1qjav7664wdt0y8tnx9z558guewnxjr3wllz2s9u",
		Amount:       5000000000,
	}
	utxo2 := &db.Utxo{
		ReceiverType: "P2WPKH",
		Receiver:     "bcrt1qjav7664wdt0y8tnx9z558guewnxjr3wllz2s9u",
		Amount:       1000000,
	}
	utxos := []*db.Utxo{utxo1, utxo2}

	hashes, err := wallet.GenerateRawMeessageToFireblocks(tx, utxos, &chaincfg.RegressionNetParams)
	require.NoError(t, err)

	require.Equal(t, len(utxos), len(hashes))

	for i, hash := range hashes {
		t.Logf("UTXO %d hash: %s", i, hex.EncodeToString(hash))
	}
}
