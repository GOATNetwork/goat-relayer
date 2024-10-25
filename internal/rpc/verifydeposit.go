package rpc

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/types"
)

func (s *UtxoServer) VerifyDeposit(tx wire.MsgTx, evmAddress string) (isTrue bool, signVersion uint32, outIdxToAmount map[int]int64, err error) {
	network := types.GetBTCNetwork(config.AppConfig.BTCNetworkType)
	outIdxToAmount = make(map[int]int64)

	pubKey, err := s.getPubKey()
	if err != nil {
		return false, 100, outIdxToAmount, err
	}

	p2wpkh, err := types.GenerateP2WPKHAddress(pubKey, network)
	if err != nil {
		return false, 100, outIdxToAmount, err
	}

	magicBytes := s.state.GetL2Info().DepositMagic
	minDepositAmount := int64(s.state.GetL2Info().MinDepositAmount)
	isTrue, _, outIdxToAmount = types.IsUtxoGoatDepositV1(&tx, []btcutil.Address{p2wpkh}, network, minDepositAmount, magicBytes)
	if isTrue {
		return true, 1, outIdxToAmount, nil
	}

	p2wsh, err := types.GenerateV0P2WSHAddress(pubKey, evmAddress, network)
	if err != nil {
		return false, 100, outIdxToAmount, err
	}

	isTrue, outIdxToAmount = types.IsUtxoGoatDepositV0(&tx, []btcutil.Address{p2wsh}, network, minDepositAmount)
	if isTrue {
		return true, 0, outIdxToAmount, nil
	}

	return false, 100, outIdxToAmount, fmt.Errorf("invalid deposit isUtxoGoatDeposit: %v, outIdxToAmount: %v", isTrue, outIdxToAmount)
}

func (s *UtxoServer) getPubKey() ([]byte, error) {
	l2Info := s.state.GetL2Info()

	var err error
	var pubKey []byte
	if l2Info.DepositKey == "" {
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
