package types

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/ethereum/go-ethereum/common"
	log "github.com/sirupsen/logrus"
)

const (
	WALLET_TYPE_P2WPKH = "P2WPKH"
	WALLET_TYPE_P2PKH  = "P2PKH"
	WALLET_TYPE_P2SH   = "P2SH"
	WALLET_TYPE_P2WSH  = "P2WSH"
	WALLET_TYPE_P2TR   = "P2TR"

	SMALL_UTXO_DEFINE = 50000000 // 0.5 BTC
)

// MsgUtxoDeposit defines deposit UTXO broadcast to p2p which received in relayer rpc
type MsgUtxoDeposit struct {
	RawTx       string `json:"raw_tx"`
	TxId        string `json:"tx_id"`
	OutputIndex int    `json:"output_index"`
	SignVersion uint32 `json:"sign_version"`
	EvmAddr     string `json:"evm_addr"`
	Amount      int64  `json:"amount"`
	Timestamp   int64  `json:"timestamp"`
}

type MsgSendOrderBroadcasted struct {
	TxId         string `json:"tx_id"`
	ExternalTxId string `json:"external_tx_id"`

	SendOrder []byte `json:"send_order"`
	Utxos     []byte `json:"utxos"`

	WithdrawIds []uint64 `json:"withdraw_ids"`
}

// MsgUtxoWithdraw defines withdraw UTXO broadcast to p2p which received in relayer rpc
type MsgUtxoWithdraw struct {
	TxId      string `json:"tx_id"`
	EvmAddr   string `json:"evm_addr"`
	Timestamp int64  `json:"timestamp"`
}

type BtcBlockExt struct {
	wire.MsgBlock

	BlockNumber uint64
}

func isOpReturn(txOut *wire.TxOut) bool {
	// Ensure the PkScript is not empty and starts with OP_RETURN
	return len(txOut.PkScript) > 0 && txOut.PkScript[0] == txscript.OP_RETURN
}

func convertVoutToTxOut(vout btcjson.Vout) (*wire.TxOut, error) {
	// Decode the ScriptPubKey hex string into bytes
	scriptPubKeyBytes, err := hex.DecodeString(vout.ScriptPubKey.Hex)
	if err != nil {
		return nil, err
	}

	// Create wire.TxOut
	txOut := &wire.TxOut{
		Value:    int64(vout.Value * 1e8), // Convert BTC to satoshis
		PkScript: scriptPubKeyBytes,
	}

	return txOut, nil
}

func parseOpReturnGoatMagic(data []byte, magicBytes []byte) (common.Address, error) {
	// Ensure the data is long enough to contain the magic bytes
	if len(data) < len(magicBytes)+1 {
		return common.Address{}, fmt.Errorf("data is too short, expected at least %d bytes, got %d", len(magicBytes), len(data))
	}
	dataLen := uint32(data[0])
	if dataLen != 24 {
		return common.Address{}, fmt.Errorf("data length is not expected 24, got %d", dataLen)
	}
	data = data[1:]
	// Check if the data starts with GOAT_MAGIC_BYTES
	if !bytes.HasPrefix(data, magicBytes) {
		return common.Address{}, errors.New("data does not start with magic bytes")
	}
	log.Debugf("Parsed OP_RETURN as GTT0: %v", data)
	remainingBytes := data[len(magicBytes):]
	// Check if the remaining bytes match the expected EVM address length (20 bytes)
	if len(remainingBytes) != 20 {
		return common.Address{}, fmt.Errorf("invalid data length for EVM address, expected 20 bytes, got %d", len(remainingBytes))
	}
	evmAddr := common.BytesToAddress(remainingBytes)
	log.Debugf("Parsed OP_RETURN EVM address: %s", evmAddr.Hex())
	return evmAddr, nil
}

func IsUtxoGoatDepositV1(tx *wire.MsgTx, tssAddress []btcutil.Address, net *chaincfg.Params, minDepositAmount int64, magicBytes []byte) (isTrue bool, evmAddr string, outIdxToAmount map[int]int64) {
	// Ensure there are at least 2 outputs, one of them is OP_RETURN
	outIdxToAmount = make(map[int]int64)

	if len(tx.TxOut) < 2 {
		return false, "", outIdxToAmount
	}
	// Check if tx.TxOut[1] is OP_RETURN and tx.TxOut[0] is not OP_RETURN
	if !isOpReturn(tx.TxOut[1]) || isOpReturn(tx.TxOut[0]) {
		return false, "", outIdxToAmount
	}
	// Extract addresses from tx.TxOut[0]
	_, addresses, requireSigs, err := txscript.ExtractPkScriptAddrs(tx.TxOut[0].PkScript, net)
	if err != nil || addresses == nil || requireSigs > 1 {
		log.Debugf("Cannot extract PkScript addresses from TxOut[0]: %v", err)
		return false, "", outIdxToAmount
	}
	// Check if any of the addresses match tssAddress
	for _, address := range tssAddress {
		if address.EncodeAddress() == addresses[0].EncodeAddress() && tx.TxOut[0].Value >= minDepositAmount {
			// check if tx.TxOut[1] OP_RETURN rule: https://www.goat.network/docs/deposit/v1
			// Process OP_RETURN to extract EVM address
			data := tx.TxOut[1].PkScript[1:] // Assuming OP_RETURN opcode is at index 0
			evmAddr, err := parseOpReturnGoatMagic(data, magicBytes)
			if err != nil {
				log.Debugf("Cannot parse OP_RETURN in TxOut[1]: %v", err)
				return false, "", outIdxToAmount
			}
			outIdxToAmount[0] = tx.TxOut[0].Value
			return true, evmAddr.Hex(), outIdxToAmount
		}
	}
	return false, "", outIdxToAmount
}

func IsUtxoGoatDepositV0(tx *wire.MsgTx, tssAddress []btcutil.Address, net *chaincfg.Params, minDepositAmount int64) (isTrue bool, outIdxToAmount map[int]int64) {
	// Ensure there are at least 1 output
	outIdxToAmount = make(map[int]int64)

	if len(tx.TxOut) < 1 {
		return false, outIdxToAmount
	}

	// Extract addresses from tx.TxOut[0]
	for idx, txOut := range tx.TxOut {

		if isOpReturn(txOut) {
			continue
		}

		_, addresses, requireSigs, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, net)
		if err != nil || addresses == nil || requireSigs > 1 {
			log.Debugf("Cannot extract PkScript addresses from TxOut[0]: %v", err)
			continue
		}

		for _, addr := range tssAddress {
			if addr.EncodeAddress() == addresses[0].EncodeAddress() && txOut.Value >= minDepositAmount {
				outIdxToAmount[idx] = txOut.Value
			}
		}
	}

	if len(outIdxToAmount) == 0 {
		return false, outIdxToAmount
	}

	return true, outIdxToAmount
}

func IsUtxoGoatDepositV0Json(tx *btcjson.TxRawResult, tssAddress []btcutil.Address, net *chaincfg.Params) (isV0 bool, outputIndex int, amount int64, pkScript []byte) {
	// Ensure there are at least 1 output
	if len(tx.Vout) < 1 {
		return false, -1, 0, nil
	}

	// Extract addresses from tx.TxOut[0]
	for idx, vout := range tx.Vout {
		txOut, err := convertVoutToTxOut(vout)
		if err != nil {
			log.Debugf("Cannot convert Vout to TxOut: %v", err)
			continue
		}

		if isOpReturn(txOut) {
			continue
		}

		_, addresses, requireSigs, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, net)
		if err != nil || addresses == nil || requireSigs > 1 {
			log.Debugf("Cannot extract PkScript addresses from TxOut[0]: %v", err)
			continue
		}

		for _, address := range tssAddress {
			if address.EncodeAddress() == addresses[0].EncodeAddress() {
				return true, idx, txOut.Value, txOut.PkScript
			}
		}
	}

	return false, -1, 0, nil
}

func GetDustAmount(txPrice int64) int64 {
	return txPrice * 31 * 3
}

func GetAddressType(addressStr string, net *chaincfg.Params) (string, error) {
	address, err := btcutil.DecodeAddress(addressStr, net)
	if err != nil {
		return "", fmt.Errorf("invalid Bitcoin address: %v", err)
	}

	switch address.(type) {
	case *btcutil.AddressPubKeyHash:
		return WALLET_TYPE_P2PKH, nil
	case *btcutil.AddressScriptHash:
		return WALLET_TYPE_P2SH, nil
	case *btcutil.AddressWitnessPubKeyHash:
		return WALLET_TYPE_P2WPKH, nil
	case *btcutil.AddressWitnessScriptHash:
		return WALLET_TYPE_P2WSH, nil
	case *btcutil.AddressTaproot:
		return WALLET_TYPE_P2TR, nil
	default:
		return "", nil
	}
}

// TransactionSizeEstimate estimates the size of a transaction in bytes
func TransactionSizeEstimate(numInputs int, receiverTypes []string, numOutputs int, utxoTypes []string) int64 {
	var totalSize int64 = 10 // Base transaction size (version, locktime, etc.)

	// Add inputs size
	for _, utxoType := range utxoTypes {
		switch utxoType {
		case WALLET_TYPE_P2WPKH:
			totalSize += 41 // P2WPKH input size without witness (32 bytes txid + 4 bytes vout + 1 byte script length + 4 bytes sequence)
		case WALLET_TYPE_P2PKH:
			totalSize += 148 // P2PKH input size
		case WALLET_TYPE_P2WSH:
			totalSize += 41 // P2WSH input size without witness (32 bytes txid + 4 bytes vout + 1 byte script length + 4 bytes sequence)
		case WALLET_TYPE_P2SH:
			totalSize += 296 // P2SH input size
		case WALLET_TYPE_P2TR:
			totalSize += 41 // P2TR input size without witness (32 bytes txid + 4 bytes vout + 1 byte script length + 4 bytes sequence)
		}
	}

	// Each output (P2PKH: 34 bytes, P2WPKH: 31 bytes, P2SH: 32 bytes, P2WSH: 43 bytes, P2TR: 42 bytes)
	for _, receiverType := range receiverTypes {
		switch receiverType {
		case WALLET_TYPE_P2PKH:
			totalSize += 34
		case WALLET_TYPE_P2WPKH:
			totalSize += 31
		case WALLET_TYPE_P2SH:
			totalSize += 32
		case WALLET_TYPE_P2WSH:
			totalSize += 43
		case WALLET_TYPE_P2TR:
			totalSize += 42
		}
	}

	if len(receiverTypes) < numOutputs {
		// change output as P2WPKH
		totalSize += int64(31 * (numOutputs - len(receiverTypes)))
	}

	return totalSize
}

func TransactionSizeEstimateV2(numInputs int, receiverTypes []string, numOutputs int, utxoTypes []string) (float64, int64) {
	// Base transaction overhead (version + locktime)
	baseSize := int64(4 + 4) // version(4) + locktime(4)
	witnessSize := int64(0)

	// Calculate input sizes
	baseSize += 1 // input count varint

	// Calculate input sizes
	for _, utxoType := range utxoTypes {
		switch utxoType {
		case WALLET_TYPE_P2WPKH:
			// Base: txid(32) + vout(4) + script_len(1) + sequence(4) = 41
			// Witness: items_count(1) + sig_len(1) + max_sig(72) + pubkey_len(1) + pubkey(33) = 108 or 107
			baseSize += 41
			// Use the maximum possible size for estimation
			witnessSize += 108
		case WALLET_TYPE_P2PKH:
			// Legacy input: txid(32) + vout(4) + script_len(1) + script(107) + sequence(4) = 148
			baseSize += 148
		case WALLET_TYPE_P2WSH:
			// Base: txid(32) + vout(4) + script_len(1) + sequence(4) = 41
			baseSize += 41
			// Witness (131 or 132 bytes):
			//   - items_count: 1 byte
			//   - sig_len: 1 byte
			//   - max_signature: 72 bytes
			//   - redeem_script_len: 1 byte
			//   - redeem_script (57 bytes):
			//     * evm_address_len: 1 byte
			//     * evm_address: 20 bytes
			//     * OP_DROP: 1 byte
			//     * pubkey_len: 1 byte
			//     * pubkey: 33 bytes
			//     * OP_CHECKSIG: 1 byte
			witnessSize += 132
		case WALLET_TYPE_P2SH:
			// Legacy P2SH input
			baseSize += 296
		case WALLET_TYPE_P2TR:
			// Base: txid(32) + vout(4) + script_len(1) + sequence(4) = 41
			baseSize += 41
			witnessSize += 66
		}
	}

	// Calculate output sizes
	baseSize += 1 // output count varint
	for _, receiverType := range receiverTypes {
		switch receiverType {
		case WALLET_TYPE_P2PKH:
			baseSize += 34 // value(8) + script_len(1) + script(25)
		case WALLET_TYPE_P2WPKH:
			baseSize += 31 // value(8) + script_len(1) + script(22)
		case WALLET_TYPE_P2SH:
			baseSize += 32 // value(8) + script_len(1) + script(23)
		case WALLET_TYPE_P2WSH:
			baseSize += 43 // value(8) + script_len(1) + script(34)
		case WALLET_TYPE_P2TR:
			baseSize += 43 // value(8) + script_len(1) + script(34)
		}
	}

	// Add change outputs (P2WPKH)
	if len(receiverTypes) < numOutputs {
		baseSize += int64(31 * (numOutputs - len(receiverTypes)))
	}

	// If there's any witness data, we need to add marker and flag bytes to witness
	if witnessSize > 0 {
		witnessSize += 2
	}

	// Virtual size = (base size * 4 + witness size) / 4
	weight := baseSize*4 + witnessSize
	virtualSize := float64(weight) / float64(4)

	return virtualSize, witnessSize
}

// Deserialize transaction
func DeserializeTransaction(data []byte) (*wire.MsgTx, error) {
	var tx wire.MsgTx
	buf := bytes.NewReader(data)
	err := tx.Deserialize(buf)
	if err != nil {
		return nil, err
	}
	return &tx, nil
}

// Serialize transaction to bytes (with witness data)
func SerializeTransaction(tx *wire.MsgTx) ([]byte, error) {
	var buf bytes.Buffer
	err := tx.Serialize(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Serialize transaction to bytes (without witness data)
func SerializeTransactionNoWitness(tx *wire.MsgTx) ([]byte, error) {
	var buf bytes.Buffer
	err := tx.SerializeNoWitness(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ConvertTxRawResultToMsgTx(txResult *btcjson.TxRawResult) (*wire.MsgTx, error) {
	// Decode the hex-encoded transaction
	txBytes, err := hex.DecodeString(txResult.Hex)
	if err != nil {
		return nil, err
	}

	// Deserialize the transaction
	msgTx := wire.NewMsgTx(wire.TxVersion)
	err = msgTx.Deserialize(bytes.NewReader(txBytes))
	if err != nil {
		return nil, err
	}

	return msgTx, nil
}
