package wallet_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/types"
	"github.com/goatnetwork/goat-relayer/internal/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// UTXO Information Structure
type UTXOInfo struct {
	Txid   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Value  int64  `json:"value"`
	Status struct {
		Confirmed   bool   `json:"confirmed"`
		BlockHeight uint64 `json:"block_height,omitempty"`
		BlockHash   string `json:"block_hash,omitempty"`
		BlockTime   int64  `json:"block_time,omitempty"`
	} `json:"status"`
}

// GetUTXOsFromMempool Retrieves the UTXO list for an address from mempool.space
func GetUTXOsFromMempool(address string, networkType string) ([]*UTXOInfo, error) {
	// Select the API base URL based on the network type
	baseURL := "https://mempool.space"
	switch networkType {
	case "testnet3":
		baseURL = "https://mempool.space/testnet"
	case "signet":
		baseURL = "https://mempool.space/signet"
	case "regtest":
		baseURL = "http://127.0.0.1:8800"
	}

	// Construct the API URL
	url := fmt.Sprintf("%s/api/address/%s/utxo", baseURL, address)

	// Create an HTTP client
	client := &http.Client{
		Timeout: time.Second * 10,
	}

	// Send a GET request
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to request the mempool API: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned a non-200 status code: %d", resp.StatusCode)
	}

	// Parse the JSON response
	var utxos []*UTXOInfo
	if err := json.NewDecoder(resp.Body).Decode(&utxos); err != nil {
		return nil, fmt.Errorf("failed to parse the JSON response: %v", err)
	}

	return utxos, nil
}

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
	selectedUtxos, totalSelectedAmount, withdrawAmount, changeAmount, estimatedFee, _, err := wallet.SelectOptimalUTXOs(utxos, []string{types.WALLET_TYPE_P2WPKH}, 40000000, 100, 1)
	assert.NoError(t, err)
	assert.NotNil(t, selectedUtxos)
	assert.Greater(t, totalSelectedAmount, int64(0))
	assert.Equal(t, int64(40000000), withdrawAmount)
	assert.Greater(t, changeAmount, int64(0))
	assert.Greater(t, estimatedFee, float64(0))

	// when not enough UTXOs
	_, _, _, _, estimatedFee, _, err = wallet.SelectOptimalUTXOs(utxos, []string{types.WALLET_TYPE_P2WPKH}, 150000000, 100, 1)
	assert.Error(t, err)
	assert.EqualError(t, err, fmt.Sprintf("not enough utxos to satisfy the withdrawal amount and network fee, withdraw amount: 150000000, selected amount: 115000000, estimated fee: %f", estimatedFee))
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
	tx, _, dustWithdraw, err := wallet.CreateRawTransaction(utxos, withdrawals, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 5000000, 1000, 10, 10, net)
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
		assert.Equal(t, int64(withdrawal.Amount)-500, tx.TxOut[i].Value) // minus fee
	}

	// when withdrawal amount is too small (dust)
	withdrawals[0].Amount = 500 // less than dust limit
	_, _, dustWithdraw, err = wallet.CreateRawTransaction(utxos, withdrawals, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 5000000, 1000, 10, 10, net)
	assert.Error(t, err)
	assert.Equal(t, uint(1), dustWithdraw) // the ID of the withdrawal with the small amount
	assert.EqualError(t, err, fmt.Sprintf("withdrawal amount too small after fee deduction: %d", withdrawals[0].Amount-500))
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

func TestSpentTimeLockP2wsh(t *testing.T) {
	t.Skip("This is a time lock test, please run it manually")
	privKeyHex := "f275e00ed707eacdc6c0bd8cd68fa3b49e5d7161c1fb8592d631c26a882b1f38"
	prevHash, err := chainhash.NewHashFromStr("9476550b6f636a63becb4b8c5656ee29958c0e50f148f4ea2269d08a4fa6f50d")
	utxoAmount := int64(48946) // input amount
	lockTime := time.Unix(1742728040, 0)

	privKeyBytes, err := hex.DecodeString(privKeyHex)
	require.NoError(t, err)
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	// Create new transaction
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.LockTime = uint32(lockTime.Unix()) // Set transaction LockTime to timelock timestamp

	// Add input - timelock UTXO
	require.NoError(t, err)
	outPoint := wire.NewOutPoint(prevHash, 0)
	txIn := wire.NewTxIn(outPoint, nil, nil)
	txIn.Sequence = 0xFFFFFFF0 // Use 0xFFFFFFF0 as sequence number for timelock transaction
	tx.AddTxIn(txIn)

	// Create timelock redeem script
	pubKey := privKey.PubKey()
	subScript, err := txscript.NewScriptBuilder().
		AddInt64(lockTime.Unix()).
		AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).
		AddOp(txscript.OP_DROP).
		AddData(pubKey.SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).Script()
	require.NoError(t, err)

	// Create P2WSH output script
	redeemScriptHash := sha256.Sum256(subScript)
	scriptAddr, err := btcutil.NewAddressWitnessScriptHash(redeemScriptHash[:], &chaincfg.TestNet3Params)
	require.NoError(t, err)

	// Create P2WPKH output address
	p2wpkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pubKey.SerializeCompressed()), &chaincfg.TestNet3Params)
	require.NoError(t, err)
	p2wpkhScript, err := txscript.PayToAddrScript(p2wpkhAddr)
	require.NoError(t, err)

	// Calculate transaction fee
	fee := int64(1000) // 1000 satoshis as fixed fee
	outputAmount := utxoAmount - fee

	// Add output
	txOut := wire.NewTxOut(outputAmount, p2wpkhScript)
	tx.AddTxOut(txOut)

	// Create input script
	prevPkScript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(redeemScriptHash[:]).Script()
	require.NoError(t, err)

	// Create signature
	inputFetcher := txscript.NewCannedPrevOutputFetcher(prevPkScript, utxoAmount)
	sigHashes := txscript.NewTxSigHashes(tx, inputFetcher)
	sig, err := txscript.RawTxInWitnessSignature(tx, sigHashes, 0, utxoAmount, subScript, txscript.SigHashAll, privKey)
	require.NoError(t, err)

	// Set witness data
	tx.TxIn[0].Witness = wire.TxWitness{sig, subScript}

	// Serialize transaction
	txBytes, err := types.SerializeTransaction(tx)
	require.NoError(t, err)
	t.Logf("txBytes: %s", hex.EncodeToString(txBytes))

	// Verify transaction
	utxo := &db.Utxo{
		ReceiverType: "P2WSH",
		Receiver:     scriptAddr.String(),
		SubScript:    subScript,
		Amount:       utxoAmount,
	}

	// Sign transaction
	err = wallet.SignTransactionByPrivKey(privKey, tx, []*db.Utxo{utxo}, &chaincfg.TestNet3Params)
	require.NoError(t, err)

	// Initialize configuration
	tempDir := t.TempDir()
	t.Setenv("DB_DIR", tempDir)
	t.Setenv("BTC_RPC", "127.0.0.1:18443")
	t.Setenv("BTC_RPC_USER", "test")
	t.Setenv("BTC_RPC_PASS", "test")
	t.Setenv("BTC_NETWORK_TYPE", "regtest")
	config.InitConfig()

	// Create Bitcoin client
	connConfig := &rpcclient.ConnConfig{
		Host:         config.AppConfig.BTCRPC,
		User:         config.AppConfig.BTCRPC_USER,
		Pass:         config.AppConfig.BTCRPC_PASS,
		HTTPPostMode: true,
		DisableTLS:   true,
	}
	btcClient, err := rpcclient.New(connConfig, nil)
	if err != nil {
		t.Fatalf("Failed to create Bitcoin client: %v", err)
	}
	defer btcClient.Shutdown()
	txid, err := btcClient.SendRawTransaction(tx, false)
	// Get the current time
	currentTime := time.Now()
	t.Logf("Txid: %s", txid)
	t.Logf("Current time: %v", currentTime)
	t.Logf("Lock time: %v", lockTime)
	// Ensure the lock time has expired
	if currentTime.Before(lockTime) {
		t.Logf("Lock time has not expired, current time: %v, lock time: %v, err: %v", currentTime, lockTime, err)
		assert.Error(t, err)
	} else {
		assert.NoError(t, err)
	}
}

// Create a time-locked transaction
func createTimeLockTransaction(btcClient *rpcclient.Client, utxo *UTXOInfo, privKey *btcutil.WIF, targetAddr string, lockTime time.Time) (*wire.MsgTx, error) {
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.LockTime = 0

	// Add input
	utxoHash, err := chainhash.NewHashFromStr(utxo.Txid)
	if err != nil {
		return nil, fmt.Errorf("Invalid UTXO hash: %v", err)
	}
	outPoint := wire.NewOutPoint(utxoHash, utxo.Vout)
	txIn := wire.NewTxIn(outPoint, nil, nil)
	txIn.Sequence = 0xFFFFFFF0 // Enable RBF
	tx.AddTxIn(txIn)

	// Create redeem script
	builder := txscript.NewScriptBuilder()
	builder.AddInt64(lockTime.Unix())
	builder.AddOp(txscript.OP_CHECKLOCKTIMEVERIFY)
	builder.AddOp(txscript.OP_DROP)
	builder.AddData(privKey.PrivKey.PubKey().SerializeCompressed())
	builder.AddOp(txscript.OP_CHECKSIG)
	redeemScript, err := builder.Script()
	if err != nil {
		return nil, fmt.Errorf("Failed to create redeem script: %v", err)
	}

	// Create P2WSH address
	redeemScriptHash := chainhash.HashB(redeemScript)
	scriptAddr, err := btcutil.NewAddressWitnessScriptHash(redeemScriptHash, &chaincfg.TestNet3Params)
	if err != nil {
		return nil, fmt.Errorf("Failed to create P2WSH address: %v", err)
	}

	// Create P2WSH output script
	scriptPubKey, err := txscript.PayToAddrScript(scriptAddr)
	if err != nil {
		return nil, fmt.Errorf("Failed to create P2WSH output script: %v", err)
	}

	// Calculate transaction fee (simplified version)
	fee := int64(1000) // 1000 satoshis as fixed fee
	txOut := wire.NewTxOut(utxo.Value-fee, scriptPubKey)
	tx.AddTxOut(txOut)

	// Get input UTXO's raw transaction
	utxoTx, err := btcClient.GetRawTransaction(utxoHash)
	if err != nil {
		return nil, fmt.Errorf("Failed to get UTXO: %v", err)
	}

	// Get original script
	utxoScript := utxoTx.MsgTx().TxOut[utxo.Vout].PkScript

	// Create signature
	prevOutputFetcher := txscript.NewCannedPrevOutputFetcher(utxoScript, utxo.Value)
	sigHashes := txscript.NewTxSigHashes(tx, prevOutputFetcher)
	sig, err := txscript.RawTxInWitnessSignature(tx, sigHashes, 0, utxo.Value, utxoScript, txscript.SigHashAll, privKey.PrivKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to create signature: %v", err)
	}

	// Set witness data
	tx.TxIn[0].Witness = wire.TxWitness{sig, privKey.PrivKey.PubKey().SerializeCompressed()}
	tx.TxIn[0].SignatureScript = nil

	// Print redeem script details
	fmt.Printf("Redeem Script Info:\n")
	fmt.Printf("1. Redeem Script: %x\n", redeemScript)
	fmt.Printf("2. Redeem Script Length: %d\n", len(redeemScript))
	fmt.Printf("3. Redeem Script Hash: %x\n", chainhash.HashB(redeemScript))
	fmt.Printf("4. Expected Witness Program Hash: %x\n", redeemScriptHash)

	return tx, nil
}

func TestCreateTimeLockP2wsh(t *testing.T) {
	t.Skip("This is a time lock test, please run it manually")
	// Set lock time to 30 seconds later (reduce waiting time)
	lockTime := time.Now().Add(30 * time.Second)
	t.Logf("Set lock time to: %v", lockTime.Unix())

	// Initialize configuration
	tempDir := t.TempDir()
	t.Setenv("DB_DIR", tempDir)
	t.Setenv("BTC_RPC", "127.0.0.1:18443")
	t.Setenv("BTC_RPC_USER", "test")
	t.Setenv("BTC_RPC_PASS", "test")
	t.Setenv("BTC_NETWORK_TYPE", "regtest")
	config.InitConfig()

	// Create Bitcoin client
	connConfig := &rpcclient.ConnConfig{
		Host:         config.AppConfig.BTCRPC,
		User:         config.AppConfig.BTCRPC_USER,
		Pass:         config.AppConfig.BTCRPC_PASS,
		HTTPPostMode: true,
		DisableTLS:   true,
	}

	btcClient, err := rpcclient.New(connConfig, nil)
	if err != nil {
		t.Fatalf("Failed to create Bitcoin client: %v", err)
	}
	defer btcClient.Shutdown()

	// Test data
	wif := "cVi1iEB39ARMhrt825f5v8eFuP5DfPkfQpgggZD1KxDjwdCCuhtq"
	wifKey, err := btcutil.DecodeWIF(wif)
	if err != nil {
		t.Fatalf("Failed to decode WIF: %v", err)
	}

	// Get address UTXO
	addr := "tb1qksncyqxd4857fa8uadklcj56a5g45zmqwjm40f"
	utxos, err := GetUTXOsFromMempool(addr, "testnet3")
	if err != nil {
		t.Fatalf("Failed to get UTXO: %v", err)
	}
	if len(utxos) == 0 {
		t.Skip("No available UTXO, skipping test")
	}

	// 1. Create time lock transaction
	tx, err := createTimeLockTransaction(btcClient, utxos[0], wifKey, addr, lockTime)
	if err != nil {
		t.Fatalf("Failed to create time lock transaction: %v", err)
	}

	// Broadcast transaction
	txHash, err := btcClient.SendRawTransaction(tx, false)
	if err != nil {
		t.Fatalf("Failed to broadcast transaction: %v", err)
	}
	t.Logf("Time lock transaction has been broadcast, transaction ID: %s", txHash.String())

}

func TestGetUTXOsFromMempool(t *testing.T) {
	// Testnet address
	testnetAddress := "bcrt1qksncyqxd4857fa8uadklcj56a5g45zmqvmzccq"
	testnetUTXOs, err := GetUTXOsFromMempool(testnetAddress, "regtest")
	if err != nil {
		t.Logf("Failed to get testnet UTXOs (possibly no UTXO for the address): %v", err)
	}
	for _, utxo := range testnetUTXOs {
		t.Logf("Testnet UTXO info:\n"+
			"  Transaction ID: %s\n"+
			"  Output Index: %d\n"+
			"  Amount: %d satoshis",
			utxo.Txid,
			utxo.Vout,
			utxo.Value)
	}
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
