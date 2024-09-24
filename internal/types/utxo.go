package types

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/ethereum/go-ethereum/common"
	log "github.com/sirupsen/logrus"
)

var (
	GOAT_MAGIC_BYTES = []byte{0x47, 0x54, 0x54, 0x30} // "GTT0"
)

// MsgUtxoDeposit defines deposit UTXO broadcast to p2p which received in relayer rpc
// TODO columns
type MsgUtxoDeposit struct {
	RawTx       string `json:"raw_tx"`
	TxId        string `json:"tx_id"`
	SignVersion uint32 `json:"sign_version"`
	EvmAddr     string `json:"evm_addr"`
	Timestamp   int64  `json:"timestamp"`
}

type BtcBlockExt struct {
	wire.MsgBlock

	BlockNumber uint64
}

func isOpReturn(txOut *wire.TxOut) bool {
	// Ensure the PkScript is not empty and starts with OP_RETURN
	return len(txOut.PkScript) > 0 && txOut.PkScript[0] == txscript.OP_RETURN
}

func parseOpReturnGoatMagic(data []byte) (common.Address, error) {
	// Ensure the data is long enough to contain the magic bytes
	if len(data) < len(GOAT_MAGIC_BYTES)+1 {
		return common.Address{}, fmt.Errorf("data is too short, expected at least %d bytes, got %d", len(GOAT_MAGIC_BYTES), len(data))
	}
	dataLen := uint32(data[0])
	if dataLen != 24 {
		return common.Address{}, fmt.Errorf("data length is not expected 24, got %d", dataLen)
	}
	data = data[1:]
	// Check if the data starts with GOAT_MAGIC_BYTES
	if !bytes.HasPrefix(data, GOAT_MAGIC_BYTES) {
		return common.Address{}, errors.New("data does not start with magic bytes")
	}
	log.Debugf("Parsed OP_RETURN as GTT0: %v", data)
	remainingBytes := data[len(GOAT_MAGIC_BYTES):]
	// Check if the remaining bytes match the expected EVM address length (20 bytes)
	if len(remainingBytes) != 20 {
		return common.Address{}, fmt.Errorf("invalid data length for EVM address, expected 20 bytes, got %d", len(remainingBytes))
	}
	evmAddr := common.BytesToAddress(remainingBytes)
	log.Debugf("Parsed OP_RETURN EVM address: %s", evmAddr.Hex())
	return evmAddr, nil
}

func IsUtxoGoatDepositV1(tx *wire.MsgTx, tssAddress []btcutil.Address, net *chaincfg.Params) (bool, string) {
	// Ensure there are at least 2 outputs
	if len(tx.TxOut) < 2 {
		return false, ""
	}
	// Check if tx.TxOut[1] is OP_RETURN and tx.TxOut[0] is not OP_RETURN
	if !isOpReturn(tx.TxOut[1]) || isOpReturn(tx.TxOut[0]) {
		return false, ""
	}
	// Extract addresses from tx.TxOut[0]
	_, addresses, requireSigs, err := txscript.ExtractPkScriptAddrs(tx.TxOut[0].PkScript, net)
	if err != nil || addresses == nil || requireSigs > 1 {
		log.Debugf("Cannot extract PkScript addresses from TxOut[0]: %v", err)
		return false, ""
	}
	// Check if any of the addresses match tssAddress
	for _, address := range tssAddress {
		if address.EncodeAddress() == addresses[0].EncodeAddress() {
			// check if tx.TxOut[1] OP_RETURN rule: https://www.goat.network/docs/deposit/v1
			// Process OP_RETURN to extract EVM address
			data := tx.TxOut[1].PkScript[1:] // Assuming OP_RETURN opcode is at index 0
			evmAddr, err := parseOpReturnGoatMagic(data)
			if err != nil {
				log.Debugf("Cannot parse OP_RETURN in TxOut[1]: %v", err)
				return false, ""
			}
			return true, evmAddr.Hex()
		}
	}
	return false, ""
}

func IsUtxoGoatDepositV0(tx *wire.MsgTx, evmAddress string, pubKey []byte, net *chaincfg.Params) bool {
	// Ensure there are at least 2 outputs
	if len(tx.TxOut) < 2 {
		return false
	}

	// Extract addresses from tx.TxOut[0]
	_, addresses, requireSigs, err := txscript.ExtractPkScriptAddrs(tx.TxOut[0].PkScript, net)
	if err != nil || addresses == nil || requireSigs > 1 {
		log.Debugf("Cannot extract PkScript addresses from TxOut[0]: %v", err)
		return false
	}

	address, err := GenerateV0P2WSHAddress(pubKey, evmAddress, net)
	if err != nil {
		log.Errorf("Cannot generate v0 P2WSH address: %v", err)
		return false
	}

	// Check if any of the addresses match tssAddress
	if address.EncodeAddress() == addresses[0].EncodeAddress() {
		return true
	}

	return false
}
