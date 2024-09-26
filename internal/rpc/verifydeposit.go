package rpc

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/types"
	relayertypes "github.com/goatnetwork/goat/x/relayer/types"
	"strings"
)

func (s *UtxoServer) VerifyDeposit(tx wire.MsgTx, evmAddress string) (isTrue bool, signVersion uint32, depositAddr string, err error) {
	var network *chaincfg.Params
	switch config.AppConfig.BTCNetworkType {
	case "":
		network = &chaincfg.MainNetParams
	case "mainnet":
		network = &chaincfg.MainNetParams
	case "regtest":
		network = &chaincfg.RegressionNetParams
	case "testnet3":
		network = &chaincfg.TestNet3Params
	}

	// invalid version: 100
	version := uint32(100)
	pubKey, err := s.getPubKey()
	if err != nil {
		return false, 100, "", err
	}

	for _, out := range tx.TxOut {
		pkScript := hex.EncodeToString(out.PkScript)
		if pkScript[:4] == "0014" {
			version = 1
			break
		} else if pkScript[:4] == "0020" {
			version = 0
			break
		} else {
			continue
		}
	}

	if version == 1 {
		p2wpkhAddr, err := types.GenerateP2WPKHAddress(pubKey, network)
		if err != nil {
			return false, 100, "", err
		}

		isTrue, _ = types.IsUtxoGoatDepositV1(&tx, []btcutil.Address{p2wpkhAddr}, network)
		if isTrue {
			return true, 1, p2wpkhAddr.EncodeAddress(), nil
		}
	} else if version == 0 {
		p2wshAddr, err := types.GenerateV0P2WSHAddress(pubKey, evmAddress, network)
		if err != nil {
			return false, 100, "", err
		}

		key := relayertypes.DecodePublicKey(pubKey)

		isTrue = types.IsUtxoGoatDepositV0(key, &tx, evmAddress, p2wshAddr, network)
		if isTrue {
			return true, 0, p2wshAddr.EncodeAddress(), nil
		}
	}

	return false, 100, "", errors.New("invalid deposit address")
}

func (s *UtxoServer) getPubKey() ([]byte, error) {
	l2Info := s.state.GetL2Info()

	var err error
	var pubKey []byte
	if l2Info.DepositKey == "," || l2Info.DepositKey == "" {
		depositPubKey, err := s.state.GetDepositKeyByBtcBlock(0)
		if err != nil {
			return nil, err
		}
		pubKey, err = base64.StdEncoding.DecodeString(depositPubKey.PubKey)
		if err != nil {
			return nil, err
		}
	} else {
		pubKeyStr := strings.Split(l2Info.DepositKey, ",")[1]
		pubKey, err = base64.StdEncoding.DecodeString(pubKeyStr)
		if err != nil {
			return nil, err
		}
	}

	return pubKey, nil
}
