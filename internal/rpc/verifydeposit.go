package rpc

import (
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/types"
)

func (s *UtxoServer) VerifyDeposit(tx wire.MsgTx, evmAddress string) (isTrue bool, signVersion uint32, err error) {
	network := types.GetBTCNetwork(config.AppConfig.BTCNetworkType)

	// invalid version: 100
	version := uint32(100)
	pubKey, err := s.state.GetPubKey()
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
		p2wshAddr, err := types.GenerateP2WSHAddress(pubKey, evmAddress, network)
		if err != nil {
			return false, 100, "", err
		}

		newKey := append([]byte{0}, pubKey...)
		key := relayertypes.DecodePublicKey(newKey)

		isTrue = types.IsUtxoGoatDepositV0(key, &tx, evmAddress, p2wshAddr, network)
		if isTrue {
			return true, 0, p2wshAddr.EncodeAddress(), nil
		}
	}

	return false, 100, "", errors.New("invalid deposit address")
}
