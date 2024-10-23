package wallet

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

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
	if networkFee > int64(config.AppConfig.BTCMaxNetworkFee-300) {
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
	// sort utxos by amount from large to small
	sort.Slice(utxos, func(i, j int) bool {
		return utxos[i].Amount > utxos[j].Amount
	})

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

	// total target includes withdrawal amount and estimated fee
	totalTarget := withdrawAmount + estimatedFee

	// try to find UTXO that satisfies the total target including fee
	for _, utxo := range utxos {
		if totalSelectedAmount >= totalTarget {
			break
		}
		selectedUTXOs = append(selectedUTXOs, utxo)
		totalSelectedAmount += utxo.Amount

		// update transaction size and estimated fee with the current UTXO selection
		utxoTypes = append(utxoTypes, utxo.ReceiverType)
		txSize = types.TransactionSizeEstimate(len(selectedUTXOs), receiverTypes, withdrawTotal, utxoTypes)
		estimatedFee = txSize * networkFee

		// recalculate the total target (withdraw amount + estimated fee)
		totalTarget = withdrawAmount // + estimatedFee

		// limit max vin
		if len(selectedUTXOs) >= maxVin {
			break
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
		totalTarget = withdrawAmount // + estimatedFee, fee should minus from withdraw txout value
	}

	// after selecting, check if we have enough UTXO to cover the total target
	if totalSelectedAmount < totalTarget {
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
//	net - bitcoin network
//
// Returns:
//
//	selectedWithdrawals - selected withdrawals
//	minTxPrice - minimum transaction price
//	error - error if any
func SelectWithdrawals(withdrawals []*db.Withdraw, networkFee int64, maxVout int, net *chaincfg.Params) ([]*db.Withdraw, []string, int64, int64, error) {
	// if network fee is too high, do not perform withdrawal
	if networkFee > int64(config.AppConfig.BTCMaxNetworkFee) {
		return nil, nil, 0, 0, fmt.Errorf("network fee too high, no withdrawals allowed")
	}

	// sort withdrawals by MaxTxFee in descending order
	sort.Slice(withdrawals, func(i, j int) bool {
		return withdrawals[i].TxPrice > withdrawals[j].TxPrice
	})

	// three groups
	var group1 []*db.Withdraw
	var group2 []*db.Withdraw
	var group3 []*db.Withdraw
	uNetworkFee := uint64(networkFee)

	// iterate withdrawals and group by MaxTxFee
	for _, withdrawal := range withdrawals {
		// skip dust withdrawals first
		if withdrawal.Amount <= uint64(types.GetDustAmount(networkFee)) {
			continue
		}
		// group1: TxPrice > 150 and TxPrice >= networkFee.FeePerByte
		if withdrawal.TxPrice > 150 && withdrawal.TxPrice >= uNetworkFee {
			group1 = append(group1, withdrawal)
		} else if withdrawal.TxPrice > 50 && withdrawal.TxPrice <= 150 && withdrawal.TxPrice >= uNetworkFee {
			// group2: 50 < MaxTxFee <= 150 and MaxTxFee >= networkFee.FeePerByte
			group2 = append(group2, withdrawal)
		} else if withdrawal.TxPrice <= 50 && withdrawal.TxPrice >= uNetworkFee {
			// group3: MaxTxFee <= 50 and MaxTxFee >= networkFee
			group3 = append(group3, withdrawal)
		}
	}

	// group withdrawals and calculate the estimated fee
	applyGroup := func(group []*db.Withdraw, multiplier float64) ([]*db.Withdraw, []string, int64, int64) {
		if len(group) == 0 {
			return nil, nil, 0, 0
		}

		// limit the number of withdrawals to maxVout
		if len(group) > maxVout {
			group = group[:maxVout]
		}

		receiverTypes := make([]string, len(group))
		withdrawAmount := uint64(0)
		// calculate the minimum MaxTxFee in the group
		groupMinPrice := group[0].TxPrice
		for i, withdrawal := range group {
			if withdrawal.TxPrice < groupMinPrice {
				groupMinPrice = withdrawal.TxPrice
			}
			withdrawAmount += withdrawal.Amount
			receiverTypes[i], _ = types.GetAddressType(withdrawal.To, net)
		}

		// actual price is the minimum of networkFee * multiplier and the minimum MaxTxPrice in the group
		estimatedPrice := int64(float64(networkFee) * multiplier)
		actualPrice := int64(groupMinPrice)
		if estimatedPrice < int64(actualPrice) {
			actualPrice = estimatedPrice
		}

		return group, receiverTypes, int64(withdrawAmount), actualPrice
	}

	// process group1 (MaxTxFee > 150, fee: networkFee * 1.25 or min MaxTxFee in the group)
	if len(group1) > 0 {
		selectedWithdrawals, receiverTypes, withdrawAmount, minTxPrice := applyGroup(group1, 1.25)
		return selectedWithdrawals, receiverTypes, withdrawAmount, minTxPrice, nil
	}

	// process group2 (50 < MaxTxFee <= 150, fee: networkFee * 1.1 or min MaxTxFee in the group)
	if len(group2) > 0 {
		selectedWithdrawals, receiverTypes, withdrawAmount, minTxPrice := applyGroup(group2, 1.1)
		return selectedWithdrawals, receiverTypes, withdrawAmount, minTxPrice, nil
	}

	// process group3 (MaxTxFee <= 50, fee: networkFee)
	if len(group3) > 0 {
		selectedWithdrawals, receiverTypes, withdrawAmount, minTxPrice := applyGroup(group3, 1.0)
		return selectedWithdrawals, receiverTypes, withdrawAmount, minTxPrice, nil
	}

	// no withdrawals found
	return nil, nil, 0, 0, fmt.Errorf("no withdrawals found")
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
		tx.AddTxIn(wire.NewTxIn(outPoint, nil, nil))
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
			// Decode the address from the UTXO receiver
			addr, err := btcutil.DecodeAddress(utxo.Receiver, net)
			if err != nil {
				return err
			}

			// Get the scriptPubKey from the address
			pkScript, err := txscript.PayToAddrScript(addr)
			if err != nil {
				return err
			}

			// Ensure the hash of the subScript matches the hash in the scriptPubKey
			subScriptHash := sha256.Sum256(utxo.SubScript)
			expectedPkScript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(subScriptHash[:]).Script()
			if err != nil {
				return err
			}
			if !bytes.Equal(pkScript, expectedPkScript) {
				return fmt.Errorf("subScript hash does not match the scriptPubKey of the UTXO")
			}

			// Create the inputFetcher with the correct scriptPubKey and amount
			inputFetcher := txscript.NewCannedPrevOutputFetcher(pkScript, utxo.Amount)

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

			// Build witness (sig + pubkey)
			witness := wire.TxWitness{
				derSignature, // Signature
				pubKeyBytes,  // Public key
			}

			// Apply the witness to the transaction input
			tx.TxIn[i].Witness = witness

		// P2WSH
		case types.WALLET_TYPE_P2WSH:
			// Decode the subscript and public key
			pubKeyBytes, err := hex.DecodeString(signedMessage.PublicKey)
			if err != nil {
				return fmt.Errorf("error decoding public key: %v", err)
			}

			// Build witness (sig + pubkey + subScript)
			witness := wire.TxWitness{
				derSignature,   // Signature
				pubKeyBytes,    // Public key
				utxo.SubScript, // The redeem script (subscript)
			}

			// Apply the witness to the transaction input
			tx.TxIn[i].Witness = witness

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
