package types

import (
	"encoding/hex"
	"slices"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"

	"crypto/sha256"

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

func GenerateP2WSHAddress(pubKey []byte, evmAddress string, net *chaincfg.Params) (*btcutil.AddressWitnessScriptHash, error) {
	posPubkey, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		return nil, err
	}
	addr, err := hex.DecodeString(evmAddress)
	if err != nil {
		return nil, err
	}

	redeemScript, err := txscript.NewScriptBuilder().
		AddData(addr[:]).
		AddOp(txscript.OP_DROP).
		AddData(posPubkey.SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).Script()
	if err != nil {
		log.Errorf("Build redeem script err: %v", err)
		return nil, err
	}

	witnessProg := sha256.Sum256(redeemScript)
	p2wsh, err := btcutil.NewAddressWitnessScriptHash(witnessProg[:], net)
	if err != nil {
		log.Errorf("Build v0 p2wsh err: %v", err)
		return nil, err
	}

	return p2wsh, nil
}
