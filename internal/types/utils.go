package types

import (
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/crypto"
	log "github.com/sirupsen/logrus"
)

func DecodeBtcHash(hash string) ([]byte, error) {
	data, err := hex.DecodeString(hash)
	if err != nil {
		return nil, err
	}
	txid := slices.Clone(data)
	slices.Reverse(txid)
	return txid, nil
}

func GetBTCNetwork(networkType string) *chaincfg.Params {
	switch networkType {
	case "", "mainnet":
		return &chaincfg.MainNetParams
	case "regtest":
		return &chaincfg.RegressionNetParams
	case "testnet3":
		return &chaincfg.TestNet3Params
	default:
		return &chaincfg.MainNetParams
	}
}

// WithdrawalWaitTime returns the time duration for the first withdraw and the time duration for the second withdraw
func WithdrawalWaitTime(networkType string) (time.Duration, time.Duration) {
	switch networkType {
	case "regtest":
		return 5 * time.Minute, 10 * time.Minute
	case "testnet3":
		// testnet3 block speed is 10 minutes, so wait time is 10 minutes, 20 minutes
		// TODO: restore after testnet upgrade
		return 10 * time.Minute, 20 * time.Minute
	default:
		// mainnet 10 minutes, 20 minutes
		return 10 * time.Minute, 20 * time.Minute
	}
}

func PrivateKeyToGethAddress(privateKeyHex string) (string, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		log.Errorf("Failed to decode private key: %v", err)
		return "", err
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		log.Errorf("Failed to parse private key: %v", err)
		return "", err
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	return address.Hex(), nil
}

func PrivateKeyToGoatAddress(privateKeyHex string, accountPrefix string) (string, error) {
	sdkConfig := sdk.GetConfig()
	sdkConfig.SetBech32PrefixForAccount(accountPrefix, accountPrefix+sdk.PrefixPublic)

	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		log.Errorf("Failed to decode private key: %v", err)
		return "", err
	}
	privateKey := &secp256k1.PrivKey{Key: privateKeyBytes}
	return sdk.AccAddress(privateKey.PubKey().Address().Bytes()).String(), nil
}

func IsTargetP2PKHAddress(script []byte, targetAddress btcutil.Address, net *chaincfg.Params) bool {
	addressHash, err := btcutil.NewAddressPubKeyHash(script[3:23], net)
	if err != nil {
		return false
	}
	return addressHash.EncodeAddress() == targetAddress.EncodeAddress()
}

func IsTargetP2WPKHAddress(script []byte, targetAddress btcutil.Address, net *chaincfg.Params) bool {
	// P2WPKH is 22 bytes (0x00 + 0x14 + 20 hash)
	if len(script) != 22 || script[0] != 0x00 || script[1] != 0x14 {
		return false
	}

	pubKeyHash := script[2:22]
	address, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, net)
	if err != nil {
		return false
	}

	return address.EncodeAddress() == targetAddress.EncodeAddress()
}

func IsP2WSHAddress(script []byte, net *chaincfg.Params) (bool, string) {
	// P2WSH is 34 bytes (0x00 + 0x20 + 32 hash)
	if len(script) != 34 || script[0] != 0x00 || script[1] != 0x20 {
		return false, ""
	}

	witnessHash := script[2:34]
	address, err := btcutil.NewAddressWitnessScriptHash(witnessHash, net)
	if err != nil {
		return false, ""
	}

	return true, address.EncodeAddress()
}

func GenerateP2PKHAddress(pubKey []byte, net *chaincfg.Params) (*btcutil.AddressPubKeyHash, error) {
	pubKeyHash := btcutil.Hash160(pubKey)

	address, err := btcutil.NewAddressPubKeyHash(pubKeyHash, net)
	if err != nil {
		log.Errorf("Error generating P2PKH address: %v", err)
		return nil, err
	}

	return address, nil
}

func GenerateP2WPKHAddress(pubKey []byte, net *chaincfg.Params) (*btcutil.AddressWitnessPubKeyHash, error) {
	pubKeyHash := btcutil.Hash160(pubKey)

	address, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, net)
	if err != nil {
		log.Errorf("Error generating P2WPKH address: %v", err)
		return nil, err
	}

	return address, nil
}

func GenerateV0P2WSHAddress(pubKey []byte, evmAddress string, net *chaincfg.Params) (*btcutil.AddressWitnessScriptHash, error) {
	subScript, err := BuildSubScriptForP2WSH(evmAddress, pubKey)
	if err != nil {
		return nil, err
	}

	witnessProg := sha256.Sum256(subScript)
	p2wsh, err := btcutil.NewAddressWitnessScriptHash(witnessProg[:], net)
	if err != nil {
		return nil, fmt.Errorf("failed to create v0 p2wsh address: %v", err)
	}

	return p2wsh, nil
}

func GenerateTimeLockP2WSHAddress(pubKey []byte, lockTime time.Time, net *chaincfg.Params) (*btcutil.AddressWitnessScriptHash, []byte, error) {
	witnessScript, err := BuildTimeLockScriptForP2WSH(pubKey, lockTime, net)
	if err != nil {
		return nil, nil, err
	}

	witnessProg := sha256.Sum256(witnessScript)
	p2wsh, err := btcutil.NewAddressWitnessScriptHash(witnessProg[:], net)
	if err != nil {
		return nil, witnessScript, fmt.Errorf("failed to create timelock p2wsh address: %v", err)
	}

	return p2wsh, witnessScript, nil
}

func GenerateSPVProof(txHash string, txHashes []string) ([]byte, []byte, int, error) {
	// Find the transaction's position in the block
	txIndex := -1
	for i, hash := range txHashes {
		if hash == txHash {
			txIndex = i
			break
		}
	}

	if txIndex == -1 {
		return nil, nil, -1, fmt.Errorf("transaction hash not found in block, expected txid: %s, found txhashes: %s", txHash, txHashes)
	}

	// Generate merkle root and proof
	txHashesPtrs := make([]*chainhash.Hash, len(txHashes))
	for i, hashStr := range txHashes {
		hash, err := chainhash.NewHashFromStr(hashStr)
		if err != nil {
			return nil, nil, -1, fmt.Errorf("failed to parse transaction hash: %v", err)
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

	return merkleRoot.CloneBytes(), buf.Bytes(), txIndex, nil
}

func VerifyBlockSPV(btcBlock BtcBlockExt) error {
	// get merkle root from header
	expectedMerkleRoot := btcBlock.Header.MerkleRoot

	// generate actual merkle root from transactions
	var txHashes []*chainhash.Hash
	for _, tx := range btcBlock.Transactions {
		txHash := tx.TxHash()
		txHashes = append(txHashes, &txHash)
	}
	actualMerkleRoot := buildMerkleRoot(txHashes)

	// check merkle root is match
	if !actualMerkleRoot.IsEqual(&expectedMerkleRoot) {
		return fmt.Errorf("merkle root mismatch: expected %s, got %s",
			expectedMerkleRoot, actualMerkleRoot)
	}

	// check header hash is match
	headerHash := btcBlock.Header.BlockHash()
	blockHash := btcBlock.BlockHash()
	if !headerHash.IsEqual(&blockHash) {
		return fmt.Errorf("block hash mismatch: expected %s, got %s", blockHash, headerHash)
	}

	log.Infof("Block %d SPV verification successful: Merkle root and block hash match", btcBlock.BlockNumber)
	return nil
}

// buildMerkleRoot builds the Merkle tree and returns the root hash
func buildMerkleRoot(txHashes []*chainhash.Hash) *chainhash.Hash {
	if len(txHashes) == 0 {
		return nil
	}

	// Merkle Root calculation loop
	for len(txHashes) > 1 {
		var newLevel []*chainhash.Hash

		// combine hashes two by two
		for i := 0; i < len(txHashes); i += 2 {
			var combined []byte
			if i+1 < len(txHashes) {
				// normal case: combine two by two
				combined = append(txHashes[i][:], txHashes[i+1][:]...)
			} else {
				// odd case: duplicate the last transaction hash
				combined = append(txHashes[i][:], txHashes[i][:]...)
			}
			newHash := chainhash.DoubleHashH(combined)
			newLevel = append(newLevel, &newHash)
		}

		// prepare for the next level
		txHashes = newLevel
	}

	// return the final root hash
	return txHashes[0]
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

func BuildSubScriptForP2WSH(evmAddress string, pubKey []byte) ([]byte, error) {
	posPubkey, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	evmAddress = strings.TrimPrefix(evmAddress, "0x")
	addr, err := hex.DecodeString(evmAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to decode evmAddress: %v", err)
	}

	subScript, err := txscript.NewScriptBuilder().
		AddData(addr).
		AddOp(txscript.OP_DROP).
		AddData(posPubkey.SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).Script()
	if err != nil {
		return nil, fmt.Errorf("failed to build subscript: %v", err)
	}
	return subScript, nil
}

func BuildTimeLockScriptForP2WSH(pubKey []byte, lockTime time.Time, net *chaincfg.Params) ([]byte, error) {
	posPubkey, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	subScript, err := txscript.NewScriptBuilder().
		AddInt64(lockTime.Unix()).
		AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).
		AddOp(txscript.OP_DROP).
		AddData(posPubkey.SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).Script()
	if err != nil {
		return nil, fmt.Errorf("failed to build subscript: %v", err)
	}
	return subScript, nil
}

func ParseRSAPublicKeyFromPEM(pubKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	pubKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return pubKey, nil
}

func ParseRSAPrivateKeyFromPEM(privKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privKeyPEM))
	if block == nil || block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	var parsedKey interface{}
	var err error

	if block.Type == "PRIVATE KEY" {
		parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	} else if block.Type == "RSA PRIVATE KEY" {
		parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	privKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	return privKey, nil
}

func IndexOfSlice(sl []string, s string) int {
	for i, addr := range sl {
		if addr == s {
			return i
		}
	}
	return -1
}

func Threshold(total int) int {
	// >= 2/3
	return (total*2 + 2) / 3
}
