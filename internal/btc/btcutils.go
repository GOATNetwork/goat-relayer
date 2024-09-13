package btc

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func GenerateSPVProof(txHash string, txHashes []string) ([]byte, []byte, uint32, error) {
	// Find the transaction's position in the block
	var txIndex int
	for i, hash := range txHashes {
		if hash == txHash {
			txIndex = i
			break
		}
	}

	// Generate merkle root and proof
	txHashesPtrs := make([]*chainhash.Hash, len(txHashes))
	for i, hashStr := range txHashes {
		hash, err := chainhash.NewHashFromStr(hashStr)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to parse transaction hash: %v", err)
		}
		txHashesPtrs[i] = hash
	}
	var proof []*chainhash.Hash
	merkleRoot := ComputeMerkleRootAndProof(txHashesPtrs, txIndex, &proof)

	// Serialize immediate proof
	var buf bytes.Buffer
	for _, p := range proof {
		buf.Write(p[:])
	}

	return merkleRoot.CloneBytes(), buf.Bytes(), uint32(txIndex), nil
}

func SerializeNoWitnessTx(rawTransaction []byte) ([]byte, error) {
	// Parse the raw transaction
	rawTx := wire.NewMsgTx(wire.TxVersion)
	err := rawTx.Deserialize(bytes.NewReader(rawTransaction))
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw transaction: %v", err)
	}

	// Create a new transaction without witness data
	noWitnessTx := wire.NewMsgTx(rawTx.Version)

	// Copy transaction inputs, excluding witness data
	for _, txIn := range rawTx.TxIn {
		newTxIn := wire.NewTxIn(&txIn.PreviousOutPoint, nil, nil)
		newTxIn.Sequence = txIn.Sequence
		noWitnessTx.AddTxIn(newTxIn)
	}

	// Copy transaction outputs
	for _, txOut := range rawTx.TxOut {
		noWitnessTx.AddTxOut(txOut)
	}

	// Set lock time
	noWitnessTx.LockTime = rawTx.LockTime

	// Serialize the transaction without witness data
	var buf bytes.Buffer
	err = noWitnessTx.Serialize(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize transaction without witness data: %v", err)
	}

	return buf.Bytes(), nil
}

func VerifyTransaction(rawTransaction []byte) error {
	if len(rawTransaction) == 0 {
		return fmt.Errorf("raw transaction is empty")
	}

	// TODO: Implement more detailed verification

	tx := wire.NewMsgTx(wire.TxVersion)
	err := tx.Deserialize(bytes.NewReader(rawTransaction))
	if err != nil {
		return fmt.Errorf("failed to parse raw transaction: %v", err)
	}

	return nil
}
