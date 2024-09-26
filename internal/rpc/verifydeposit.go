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
	"strings"
)

func (s *UtxoServer) VerifyDeposit(tx wire.MsgTx, evmAddress string) (isTrue bool, signVersion uint32, err error) {
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

	pubKey, err := s.getPubKey()
	if err != nil {
		return false, 100, err
	}

	version := uint32(100)
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
		p2wpkh, err := types.GenerateP2WPKHAddress(pubKey, network)
		if err != nil {
			return false, 100, err
		}

		isTrue, _ = types.IsUtxoGoatDepositV1(&tx, []btcutil.Address{p2wpkh}, network)
		if isTrue {
			return true, 1, nil
		}
	} else if version == 0 {
		isTrue = types.IsUtxoGoatDepositV0(&tx, evmAddress, pubKey, network)
		if isTrue {
			return true, 0, nil
		}
	}

	return false, 100, errors.New("invalid deposit address")
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
