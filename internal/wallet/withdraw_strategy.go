package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/types"
	log "github.com/sirupsen/logrus"
)

// ConsolidateSmallUTXOs consolidate small utxos
//
// Parameters:
//
//	utxos - all unspent utxos
//	networkFee - network fee
//	threshold - threshold for small utxos
//	maxVin - maximum vin count
//	trigerNum - minimum small utxo
//
// Returns:
//
//	selectedUtxos - selected utxos for consolidation
//	totalAmount - total amount of selected utxos
//	finalAmount - final amount after consolidation, after deducting the network fee
//	error - error if any
func ConsolidateSmallUTXOs(utxos []*db.Utxo, networkFee, threshold int64, maxVin, trigerNum int) ([]*db.Utxo, int64, int64, error) {
	if networkFee > int64(config.AppConfig.BTCMaxNetworkFee) {
		return nil, 0, 0, fmt.Errorf("network fee is too high, cannot consolidate")
	}
	if trigerNum < 10 {
		trigerNum = 500
	}
	if len(utxos) < trigerNum {
		return nil, 0, 0, fmt.Errorf("not enough utxos to consolidate")
	}

	var smallUTXOs []*db.Utxo
	var totalAmount int64 = 0

	// select lower than threshold (0.5 BTC)
	for _, utxo := range utxos {
		if utxo.ReceiverType != types.WALLET_TYPE_P2WPKH && utxo.ReceiverType != types.WALLET_TYPE_P2WSH && utxo.ReceiverType != types.WALLET_TYPE_P2PKH {
			continue
		}
		if utxo.Amount < threshold {
			smallUTXOs = append(smallUTXOs, utxo)
			totalAmount += utxo.Amount
		}
		// vin count limit
		if len(smallUTXOs) >= maxVin {
			break
		}
	}

	if len(smallUTXOs) < trigerNum {
		return nil, 0, 0, fmt.Errorf("not enough small utxos to consolidate")
	}

	// calculate transaction size and estimated fee
	utxoTypes := make([]string, len(smallUTXOs))
	for i, utxo := range smallUTXOs {
		utxoTypes[i] = utxo.ReceiverType
	}

	txSize := types.TransactionSizeEstimate(len(smallUTXOs), []string{types.WALLET_TYPE_P2WPKH}, 1, utxoTypes) // 1 vout
	estimatedFee := txSize * networkFee

	if totalAmount < types.GetDustAmount(networkFee) {
		return nil, 0, 0, fmt.Errorf("total amount is too low, cannot consolidate")
	}

	// calculate the remaining amount after consolidation
	finalAmount := totalAmount - estimatedFee
	if finalAmount <= 0 {
		return nil, 0, 0, fmt.Errorf("consolidation fee is too high, cannot consolidate")
	}

	return smallUTXOs, totalAmount, finalAmount, nil
}

// ConsolidateUTXOsByCount consolidate utxos by count
func ConsolidateUTXOsByCount(utxos []*db.Utxo, networkFee int64, maxVin, trigerNum int) (selectedUTXOs []*db.Utxo, totalAmount int64, finalAmount int64, err error) {
	if networkFee > int64(config.AppConfig.BTCMaxNetworkFee) {
		return nil, 0, 0, fmt.Errorf("network fee is too high, cannot consolidate")
	}
	if len(utxos) < trigerNum {
		return nil, 0, 0, fmt.Errorf("not enough utxos to consolidate")
	}

	// select all utxos until maxVin
	for _, utxo := range utxos {
		if utxo.ReceiverType != types.WALLET_TYPE_P2WPKH && utxo.ReceiverType != types.WALLET_TYPE_P2WSH && utxo.ReceiverType != types.WALLET_TYPE_P2PKH {
			continue
		}
		selectedUTXOs = append(selectedUTXOs, utxo)
		totalAmount += utxo.Amount
		// vin count limit
		if len(selectedUTXOs) >= maxVin {
			break
		}
	}

	// calculate transaction size and estimated fee
	utxoTypes := make([]string, len(selectedUTXOs))
	for i, utxo := range selectedUTXOs {
		utxoTypes[i] = utxo.ReceiverType
	}

	txSize := types.TransactionSizeEstimate(len(selectedUTXOs), []string{types.WALLET_TYPE_P2WPKH}, 1, utxoTypes) // 1 vout
	estimatedFee := txSize * networkFee

	if totalAmount < types.GetDustAmount(networkFee) {
		return nil, 0, 0, fmt.Errorf("total amount is too low, cannot consolidate")
	}

	// calculate the remaining amount after consolidation
	finalAmount = totalAmount - estimatedFee
	if finalAmount <= 0 {
		return nil, 0, 0, fmt.Errorf("consolidation fee is too high, cannot consolidate")
	}

	return selectedUTXOs, totalAmount, finalAmount, nil
}

// SelectOptimalUTXOs select optimal utxos for withdrawal
//
// Parameters:
//
//	utxos - all unspent utxos
//	withdrawAmount - total amount to withdraw
//	networkFee - network fee
//	withdrawTotal - total number of withdrawals
//
// Returns:
//
//	selectedUtxos - selected utxos for withdrawal
//	totalSelectedAmount - total amount of selected utxos
//	withdrawAmount - total amount to withdraw (not minus tx fee yet)
//	changeAmount - change amount after withdrawal
//	estimatedFee - estimate fee
//	error - error if any
func SelectOptimalUTXOs(utxos []*db.Utxo, receiverTypes []string, withdrawAmount, networkFee int64, withdrawTotal int) ([]*db.Utxo, int64, int64, int64, int64, error) {
	var selectedUTXOs []*db.Utxo
	var totalSelectedAmount int64 = 0
	var maxVin int = 10
	if withdrawAmount > 50*1e8 {
		// max vin is 50 for large amount than 50 BTC
		maxVin = 50
	}

	// calculate the current transaction fee with no UTXO selected yet
	utxoTypes := make([]string, 0)
	txSize := types.TransactionSizeEstimate(len(utxoTypes), receiverTypes, withdrawTotal, utxoTypes) // +1 for change output
	estimatedFee := txSize * networkFee

	// sort utxos by amount from small to large
	sort.Slice(utxos, func(i, j int) bool {
		return utxos[i].Amount < utxos[j].Amount
	})

	found := false

	// try to find a utxo or two utxos combination that just meets withdrawAmount
	for i := 0; i < len(utxos); i++ {
		// if current utxo amount is greater than or equal to withdrawAmount, directly select it
		if utxos[i].Amount >= withdrawAmount {
			selectedUTXOs = []*db.Utxo{utxos[i]}
			totalSelectedAmount = utxos[i].Amount
			utxoTypes = []string{utxos[i].ReceiverType}
			found = true
			log.Debugf("SelectOptimalUTXOs found single utxo matched: %s-%d, amount: %d", utxos[i].Txid, utxos[i].OutIndex, utxos[i].Amount)
			break
		}
	}
	// try to find two utxos combination that just meets withdrawAmount
	if !found {
		// if two utxos amount is greater than or equal to withdrawAmount, select them
		for i := 1; i < len(utxos); i++ {
			if utxos[i-1].Amount+utxos[i].Amount >= withdrawAmount {
				selectedUTXOs = []*db.Utxo{utxos[i-1], utxos[i]}
				totalSelectedAmount = utxos[i-1].Amount + utxos[i].Amount
				utxoTypes = []string{utxos[i-1].ReceiverType, utxos[i].ReceiverType}
				found = true
				log.Debugf("SelectOptimalUTXOs found two utxos matched: %s-%d, %s-%d, amount: %d", utxos[i-1].Txid, utxos[i-1].OutIndex, utxos[i].Txid, utxos[i].OutIndex, utxos[i-1].Amount+utxos[i].Amount)
				break
			}
		}
	}
	// if found a suitable utxo or combination, calculate transaction size and fee
	if found {
		txSize = types.TransactionSizeEstimate(len(selectedUTXOs), receiverTypes, withdrawTotal, utxoTypes)
		estimatedFee = txSize * networkFee
		// totalTarget = withdrawAmount + estimatedFee // not used, fee should minus from withdraw txout value
	} else {
		// if not found a suitable utxo or combination, accumulate utxos by amount from large to small
		sort.Slice(utxos, func(i, j int) bool {
			return utxos[i].Amount > utxos[j].Amount
		})

		// accumulate utxos by amount from large to small until totalTarget is met
		for _, utxo := range utxos {
			if totalSelectedAmount >= withdrawAmount {
				break
			}
			selectedUTXOs = append(selectedUTXOs, utxo)
			totalSelectedAmount += utxo.Amount

			// update transaction size and fee
			utxoTypes = append(utxoTypes, utxo.ReceiverType)
			txSize = types.TransactionSizeEstimate(len(selectedUTXOs), receiverTypes, withdrawTotal, utxoTypes)
			estimatedFee = txSize * networkFee

			// recalculate totalTarget (withdrawAmount + estimatedFee)
			// totalTarget = withdrawAmount + estimatedFee // not used, fee should minus from withdraw txout value

			// limit max vin
			if len(selectedUTXOs) >= maxVin {
				break
			}
		}
	}

	// find the smallest utxo and append to selected utxos
	var smallestUTXO *db.Utxo
	for _, utxo := range utxos {
		// skip already selected utxos
		isAlreadySelected := false
		for _, selected := range selectedUTXOs {
			if selected.Txid == utxo.Txid && selected.OutIndex == utxo.OutIndex {
				isAlreadySelected = true
				break
			}
		}
		if isAlreadySelected {
			continue
		}

		// if find a smaller utxo, update the smallest utxo
		if smallestUTXO == nil || utxo.Amount < smallestUTXO.Amount {
			smallestUTXO = utxo
		}
	}

	// append the smallest utxo
	if smallestUTXO != nil && smallestUTXO.Amount > 0 &&
		smallestUTXO.Amount > networkFee*(296+31) &&
		smallestUTXO.Amount < types.SMALL_UTXO_DEFINE {
		selectedUTXOs = append(selectedUTXOs, smallestUTXO)
		totalSelectedAmount += smallestUTXO.Amount

		// update transaction size and estimated fee with the current UTXO selection
		utxoTypes = append(utxoTypes, smallestUTXO.ReceiverType)
		txSize = types.TransactionSizeEstimate(len(selectedUTXOs), receiverTypes, withdrawTotal, utxoTypes)
		estimatedFee = txSize * networkFee

		// recalculate the total target (withdraw amount + estimated fee)
		// totalTarget = withdrawAmount + estimatedFee // not used, fee should minus from withdraw txout value
	}

	// after selecting, check if we have enough UTXO to cover the total target
	if totalSelectedAmount < withdrawAmount {
		return nil, 0, 0, 0, estimatedFee, fmt.Errorf("not enough utxos to satisfy the withdrawal amount and network fee, withdraw amount: %d, selected amount: %d, estimated fee: %d", withdrawAmount, totalSelectedAmount, estimatedFee)
	}

	// calculate the change amount
	changeAmount := totalSelectedAmount - withdrawAmount // - estimatedFee, fee should minus from withdraw txout value
	if changeAmount > types.GetDustAmount(networkFee) {
		// if change amount > dust limit + network fee * 31 (P2WPKH output size), we need to add a change output
		txSize = types.TransactionSizeEstimate(len(selectedUTXOs), receiverTypes, withdrawTotal+1, utxoTypes)
		estimatedFee = txSize * networkFee
	} else {
		// no change output
		estimatedFee += changeAmount
		changeAmount = 0
	}

	return selectedUTXOs, totalSelectedAmount, withdrawAmount, changeAmount, estimatedFee, nil
}

// SelectWithdrawals select optimal withdrawals for withdrawal
//
// Parameters:
//
//	withdrawals - all withdrawals can start
//	networkFee - network fee
//	maxVout - maximum vout count
//	immediateCount - immediate count to start withdrawals
//	net - bitcoin network
//
// Returns:
//
//	selectedWithdrawals - selected withdrawals
//	minTxPrice - minimum transaction price
//	error - error if any
func SelectWithdrawals(withdrawals []*db.Withdraw, networkFee types.BtcNetworkFee, maxVout, immediateCount int, net *chaincfg.Params) ([]*db.Withdraw, []string, int64, int64, error) {
	// if network fee is too high, do not perform withdrawal
	if networkFee.FastestFee > uint64(config.AppConfig.BTCMaxNetworkFee) {
		return nil, nil, 0, 0, fmt.Errorf("network fee too high, no withdrawals allowed")
	}

	// sort withdrawals by MaxTxFee in descending order
	sort.Slice(withdrawals, func(i, j int) bool {
		return withdrawals[i].TxPrice > withdrawals[j].TxPrice
	})

	// group withdrawals based on TxPrice and network fee thresholds
	groups := make(map[string][]*db.Withdraw)
	for _, withdrawal := range withdrawals {
		// determine dust threshold for each fee category and filter dust withdrawals
		switch {
		case withdrawal.TxPrice >= networkFee.FastestFee:
			dustThreshold := uint64(types.GetDustAmount(int64(networkFee.FastestFee)))
			if withdrawal.Amount > dustThreshold {
				groups["group1"] = append(groups["group1"], withdrawal)
			}
		case withdrawal.TxPrice >= networkFee.HalfHourFee:
			dustThreshold := uint64(types.GetDustAmount(int64(networkFee.HalfHourFee)))
			if withdrawal.Amount > dustThreshold {
				groups["group2"] = append(groups["group2"], withdrawal)
			}
		case withdrawal.TxPrice >= networkFee.HourFee:
			dustThreshold := uint64(types.GetDustAmount(int64(networkFee.HourFee)))
			if withdrawal.Amount > dustThreshold {
				groups["group3"] = append(groups["group3"], withdrawal)
			}
		}
	}

	// apply group selection and condition check
	waitTime1, waitTime2 := types.WithdrawalWaitTime(config.AppConfig.BTCNetworkType)
	applyGroup := func(group []*db.Withdraw, groupFee uint64) ([]*db.Withdraw, []string, int64, int64) {
		// sort by CreatedAt in ascending order and limit to maxVout
		sort.Slice(group, func(i, j int) bool { return group[i].CreatedAt.Unix() < group[j].CreatedAt.Unix() })
		if len(group) > maxVout {
			group = group[:maxVout]
		}

		receiverTypes := make([]string, len(group))
		withdrawAmount, minTxPrice := uint64(0), group[0].TxPrice

		for i, withdrawal := range group {
			if withdrawal.TxPrice < minTxPrice {
				minTxPrice = withdrawal.TxPrice
			}
			withdrawAmount += withdrawal.Amount
			receiverTypes[i], _ = types.GetAddressType(withdrawal.To, net)
		}

		// use group fee as actual fee
		return group, receiverTypes, int64(withdrawAmount), int64(groupFee)
	}

	shouldProcess := func(selected []*db.Withdraw, immediateCount int) bool {
		return len(selected) >= immediateCount ||
			(time.Since(selected[0].CreatedAt) > waitTime1 && len(selected) >= immediateCount/3) ||
			time.Since(selected[0].CreatedAt) > waitTime2
	}

	// Process each group in priority order
	for _, g := range []struct {
		key string
		fee uint64
	}{{"group1", networkFee.FastestFee}, {"group2", networkFee.HalfHourFee}, {"group3", networkFee.HourFee}} {
		group := groups[g.key]
		if len(group) > 0 {
			selectedWithdrawals, receiverTypes, withdrawAmount, minTxPrice := applyGroup(group, g.fee)
			if shouldProcess(selectedWithdrawals, immediateCount) {
				return selectedWithdrawals, receiverTypes, withdrawAmount, minTxPrice, nil
			}
		}
	}

	// no withdrawals found
	return nil, nil, 0, 0, fmt.Errorf("no withdrawals found that meet the conditions")
}

// CreateRawTransaction create raw transaction
//
// Parameters:
//
//	utxos - all unspent utxos
//	withdrawals - all withdrawals
//	changeAddress - change address
//	changeAmount - change amount
//	net - bitcoin network
//
// Returns:
//
//	tx - raw transaction
//	dustWithdraw - value lower than dust limit withdraw id
//	error - error if any
func CreateRawTransaction(utxos []*db.Utxo, withdrawals []*db.Withdraw, changeAddress string, changeAmount, estimatedFee, networkFee int64, net *chaincfg.Params) (*wire.MsgTx, uint, error) {
	tx := wire.NewMsgTx(wire.TxVersion)

	// add utxos as transaction inputs
	for _, utxo := range utxos {
		hash, err := chainhash.NewHashFromStr(utxo.Txid)
		if err != nil {
			return nil, 0, err
		}
		outPoint := wire.NewOutPoint(hash, uint32(utxo.OutIndex))
		txIn := wire.NewTxIn(outPoint, nil, nil)
		txIn.Sequence = 0xffffff01
		tx.AddTxIn(txIn)
	}

	// actual fee for withdraw
	actualFee := int64(0)
	if len(withdrawals) > 0 {
		totalTxout := len(withdrawals)
		if changeAmount > 0 {
			totalTxout++
		}
		actualFee = estimatedFee / int64(totalTxout)
	}

	// add outputs (withdrawals)
	for _, withdrawal := range withdrawals {
		addr, err := btcutil.DecodeAddress(withdrawal.To, net)
		if err != nil {
			return nil, 0, err
		}
		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, 0, err
		}
		val := int64(withdrawal.Amount) - actualFee
		if val <= types.GetDustAmount(networkFee) {
			return nil, withdrawal.ID, fmt.Errorf("withdrawal amount too small after fee deduction: %d", val)
		}
		// re-set TxFee field
		withdrawal.TxFee = withdrawal.Amount - uint64(val)
		tx.AddTxOut(wire.NewTxOut(val, pkScript))
	}

	val := changeAmount - actualFee
	// add change output
	if val > 0 {
		changeAddr, err := btcutil.DecodeAddress(changeAddress, net)
		if err != nil {
			return nil, 0, err
		}
		changePkScript, err := txscript.PayToAddrScript(changeAddr)
		if err != nil {
			return nil, 0, err
		}
		if val <= types.GetDustAmount(networkFee) {
			return nil, 0, fmt.Errorf("change amount too small after fee deduction: %d", val)
		}
		tx.AddTxOut(wire.NewTxOut(val, changePkScript))
	}
	noWitnessTx, err := types.SerializeTransactionNoWitness(tx)
	if err != nil {
		return nil, 0, err
	}
	// recaulate real tx price and compare with user fee
	actualTxPrice := uint64(estimatedFee) / uint64(len(noWitnessTx))
	for _, withdrawal := range withdrawals {
		if actualTxPrice > withdrawal.TxPrice {
			return nil, 0, fmt.Errorf("actual tx price is higher than withdrawal tx price, withdrawal id: %d, %d > %d", withdrawal.ID, actualTxPrice, withdrawal.TxPrice)
		}
	}
	return tx, 0, nil
}

// SignTransactionByPrivKey, use PrivKey to sign the transaction, and select the corresponding signature method according to the UTXO type
//
// Parameters:
//
//	privKey - private key
//	tx - transaction
//	utxos - all unspent utxos
//	net - bitcoin network
//
// Returns:
//
//	error - error if any
func SignTransactionByPrivKey(privKey *btcec.PrivateKey, tx *wire.MsgTx, utxos []*db.Utxo, net *chaincfg.Params) error {
	for i, utxo := range utxos {
		log.Debugf("SignTransactionByPrivKey utxo: %+v", utxo)
		switch utxo.ReceiverType {
		// P2PKH
		case types.WALLET_TYPE_P2PKH:
			// P2PKH uncompressed address
			addr, err := btcutil.DecodeAddress(utxo.Receiver, net)
			if err != nil {
				return err
			}
			pkScript, err := txscript.PayToAddrScript(addr)
			if err != nil {
				return err
			}

			// create P2PKH signature script
			sigScript, err := txscript.SignatureScript(tx, i, pkScript, txscript.SigHashAll, privKey, true)
			if err != nil {
				return err
			}

			// set signature script
			tx.TxIn[i].SignatureScript = sigScript

		// P2WPKH
		case types.WALLET_TYPE_P2WPKH:
			// P2WPKH needs witness data
			addr, err := btcutil.DecodeAddress(utxo.Receiver, net)
			if err != nil {
				return err
			}
			pkScript, err := txscript.PayToAddrScript(addr)
			if err != nil {
				return err
			}

			// create witness signature
			witnessSig, err := txscript.RawTxInWitnessSignature(tx, txscript.NewTxSigHashes(tx, txscript.NewCannedPrevOutputFetcher(pkScript, utxo.Amount)), i, utxo.Amount, pkScript, txscript.SigHashAll, privKey)
			if err != nil {
				return err
			}

			// set Witness data
			tx.TxIn[i].Witness = wire.TxWitness{
				witnessSig,                             // signature
				privKey.PubKey().SerializeCompressed(), // public key
			}

		// P2WSH
		case types.WALLET_TYPE_P2WSH:
			// P2WSH needs subScript
			// assume subScript is known
			redeemScriptHash := sha256.Sum256(utxo.SubScript)
			prevPkScript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(redeemScriptHash[:]).Script()
			if err != nil {
				return err
			}

			// Create the inputFetcher with the correct scriptPubKey and amount
			inputFetcher := txscript.NewCannedPrevOutputFetcher(prevPkScript, utxo.Amount)

			// Generate the witness signature using the subScript
			witnessSig, err := txscript.RawTxInWitnessSignature(tx, txscript.NewTxSigHashes(tx, inputFetcher), i, utxo.Amount, utxo.SubScript, txscript.SigHashAll, privKey)
			if err != nil {
				return err
			}

			// Set the witness stack
			tx.TxIn[i].Witness = wire.TxWitness{
				witnessSig,     // signature
				utxo.SubScript, // subScript (redeem script)
			}

		default:
			return fmt.Errorf("unknown UTXO type: %s", utxo.ReceiverType)
		}
	}

	return nil
}

// GenerateRawMeessageToFireblocks generate the raw message to fireblocks
func GenerateRawMeessageToFireblocks(tx *wire.MsgTx, utxos []*db.Utxo, net *chaincfg.Params) ([][]byte, error) {
	hashes := make([][]byte, len(utxos)) // store the hash of each input

	for i, utxo := range utxos {
		log.Debugf("GenerateHashForTSSSignatures utxo: %+v", utxo)
		var pkScript []byte

		switch utxo.ReceiverType {
		// P2PKH
		case types.WALLET_TYPE_P2PKH:
			// P2PKH uncompressed address
			addr, err := btcutil.DecodeAddress(utxo.Receiver, net)
			if err != nil {
				return nil, err
			}
			pkScript, err = txscript.PayToAddrScript(addr)
			if err != nil {
				return nil, err
			}

			// calculate the hash of P2PKH
			hash, err := txscript.CalcSignatureHash(pkScript, txscript.SigHashAll, tx, i)
			if err != nil {
				return nil, err
			}
			hashes[i] = hash

		// P2WPKH
		case types.WALLET_TYPE_P2WPKH:
			// P2WPKH needs witness data
			addr, err := btcutil.DecodeAddress(utxo.Receiver, net)
			if err != nil {
				return nil, err
			}
			pkScript, err = txscript.PayToAddrScript(addr)
			if err != nil {
				return nil, err
			}

			// generate the PrevOutputFetcher for CalcWitnessSigHash
			inputFetcher := txscript.NewCannedPrevOutputFetcher(pkScript, utxo.Amount)

			// calculate the hash of P2WPKH
			hash, err := txscript.CalcWitnessSigHash(pkScript, txscript.NewTxSigHashes(tx, inputFetcher), txscript.SigHashAll, tx, i, utxo.Amount)
			if err != nil {
				return nil, err
			}
			hashes[i] = hash

		// P2WSH
		case types.WALLET_TYPE_P2WSH:
			// P2WSH needs subScript
			// assume subScript is known
			prevPkScript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(utxo.SubScript).Script()
			if err != nil {
				return nil, err
			}

			inputFetcher := txscript.NewCannedPrevOutputFetcher(prevPkScript, utxo.Amount)

			// calculate the hash of P2WSH
			hash, err := txscript.CalcWitnessSigHash(utxo.SubScript, txscript.NewTxSigHashes(tx, inputFetcher), txscript.SigHashAll, tx, i, utxo.Amount)
			if err != nil {
				return nil, err
			}
			hashes[i] = hash

		default:
			return nil, fmt.Errorf("unknown UTXO type: %s", utxo.ReceiverType)
		}
	}

	return hashes, nil
}

func ApplyFireblocksSignaturesToTx(tx *wire.MsgTx, utxos []*db.Utxo, fbSignedMessages []types.FbSignedMessage, net *chaincfg.Params) error {
	if len(utxos) != len(fbSignedMessages) {
		return fmt.Errorf("number of UTXOs and signed messages do not match")
	}

	for i, utxo := range utxos {
		signedMessage := fbSignedMessages[i]

		// Convert the Fireblocks signature to DER format
		derSignature, err := convertToDERSignature(signedMessage.Signature)
		if err != nil {
			return fmt.Errorf("error converting Fireblocks signature to DER: %v", err)
		}

		switch utxo.ReceiverType {
		// P2PKH
		case types.WALLET_TYPE_P2PKH:
			// Decode the public key
			pubKeyBytes, err := hex.DecodeString(signedMessage.PublicKey)
			if err != nil {
				return fmt.Errorf("error decoding public key: %v", err)
			}

			// Build signature script (sig + pubkey)
			sigScript, err := txscript.NewScriptBuilder().
				AddData(derSignature).
				AddData(pubKeyBytes).
				Script()
			if err != nil {
				return fmt.Errorf("error building signature script: %v", err)
			}

			// Apply the signature script to the transaction input
			tx.TxIn[i].SignatureScript = sigScript

		// P2WPKH
		case types.WALLET_TYPE_P2WPKH:
			// Decode the public key
			pubKeyBytes, err := hex.DecodeString(signedMessage.PublicKey)
			if err != nil {
				return fmt.Errorf("error decoding public key: %v", err)
			}

			// Apply the witness to the transaction input
			tx.TxIn[i].Witness = wire.TxWitness{
				derSignature, // Signature
				pubKeyBytes,  // Public key
			}

		// P2WSH
		case types.WALLET_TYPE_P2WSH:
			// Apply the witness to the transaction input
			tx.TxIn[i].Witness = wire.TxWitness{
				derSignature,   // Signature
				utxo.SubScript, // SubScript (redeem script)
			}

		default:
			return fmt.Errorf("unknown UTXO type: %s", utxo.ReceiverType)
		}
	}

	return nil
}

// Convert FbSignature to DER encoded signature with SIGHASH_ALL
func convertToDERSignature(fbSig types.FbSignature) ([]byte, error) {
	rBytes, err := hex.DecodeString(fbSig.R)
	if err != nil {
		return nil, fmt.Errorf("error decoding R: %v", err)
	}

	sBytes, err := hex.DecodeString(fbSig.S)
	if err != nil {
		return nil, fmt.Errorf("error decoding S: %v", err)
	}

	// Convert R and S into btcec.ModNScalar
	var rMod, sMod btcec.ModNScalar
	rMod.SetByteSlice(rBytes)
	sMod.SetByteSlice(sBytes)

	// Create a btcec signature using R and S
	signature := ecdsa.NewSignature(&rMod, &sMod)

	// Serialize the signature into DER format
	derSig := signature.Serialize()

	// Append SIGHASH_ALL (0x01)
	return append(derSig, byte(txscript.SigHashAll)), nil
}
