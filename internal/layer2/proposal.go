package layer2

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdktx "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	txtypes "github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/goatnetwork/goat-relayer/internal/config"
	bitcointypes "github.com/goatnetwork/goat/x/bitcoin/types"
	log "github.com/sirupsen/logrus"
)

func (lis *Layer2Listener) SubmitToConsensus(ctx context.Context, msg interface{}) (*coretypes.ResultTx, error) {
	var err error
	accountPrefix := config.AppConfig.GoatChainAccountPrefix
	chainID := config.AppConfig.GoatChainID
	privKeyStr := config.AppConfig.RelayerPriKey
	denom := config.AppConfig.GoatChainDenom

	lis.goatSdkOnce.Do(func() {
		sdkConfig := sdk.GetConfig()
		sdkConfig.SetBech32PrefixForAccount(accountPrefix, accountPrefix+sdk.PrefixPublic)
		sdkConfig.Seal()
	})

	amino := codec.NewLegacyAmino()
	std.RegisterLegacyAminoCodec(amino)
	authtypes.RegisterLegacyAminoCodec(amino)

	interfaceRegistry := codectypes.NewInterfaceRegistry()
	protoCodec := codec.NewProtoCodec(interfaceRegistry)
	authtypes.RegisterInterfaces(interfaceRegistry)
	std.RegisterInterfaces(interfaceRegistry)

	privKeyBytes, err := hex.DecodeString(privKeyStr)
	if err != nil {
		log.Errorf("decode private key failed: %v", err)
		return nil, err
	}
	if err := lis.checkAndReconnect(); err != nil {
		log.Errorf("check and reconnect goat client faild: %v", err)
		return nil, err
	}
	privKey := &secp256k1.PrivKey{Key: privKeyBytes}
	address := sdk.AccAddress(privKey.PubKey().Address().Bytes()).String()

	accountReq := &authtypes.QueryAccountRequest{Address: address}
	accountResp, err := lis.goatQueryClient.Account(ctx, accountReq)
	if err != nil {
		log.Errorf("query account failed: %v", err)
		return nil, err
	}

	var account sdk.AccountI
	if err = protoCodec.UnpackAny(accountResp.GetAccount(), &account); err != nil {
		log.Errorf("unpack account failed: %v", err)
		return nil, err
	}

	sequence := account.GetSequence()
	accountNumber := account.GetAccountNumber()

	txConfig := txtypes.NewTxConfig(protoCodec, txtypes.DefaultSignModes)
	txBuilder := txConfig.NewTxBuilder()

	if msgNewDeposits, msgNewBlockHashes, err := lis.convertToTypes(msg); err != nil {
		log.Errorf("convert to types failed: %v", err)
		return nil, err
	} else if msgNewDeposits != nil {
		err = txBuilder.SetMsgs(msgNewDeposits)
		if err != nil {
			log.Errorf("set msgNewDeposits failed: %v", err)
			return nil, err
		}
	} else if msgNewBlockHashes != nil {
		err = txBuilder.SetMsgs(msgNewBlockHashes)
		if err != nil {
			log.Errorf("set msgNewBlockHashes failed: %v", err)
			return nil, err
		}
	}

	// set fee
	fees := sdk.NewCoins(sdk.NewInt64Coin(denom, 100))
	txBuilder.SetGasLimit(uint64(flags.DefaultGasLimit))
	txBuilder.SetFeeAmount(fees)

	if err = txBuilder.SetSignatures(signing.SignatureV2{
		PubKey: privKey.PubKey(),
		Data: &signing.SingleSignatureData{
			SignMode:  signing.SignMode(txConfig.SignModeHandler().DefaultMode()),
			Signature: nil,
		},
		Sequence: sequence,
	}); err != nil {
		log.Errorf("set signature failed: %v", err)
		return nil, err
	}

	signerData := authsigning.SignerData{
		ChainID:       chainID,
		AccountNumber: accountNumber,
		Sequence:      sequence,
	}
	sigV2, err := tx.SignWithPrivKey(ctx, signing.SignMode(txConfig.SignModeHandler().DefaultMode()), signerData, txBuilder, privKey, txConfig, sequence)
	if err != nil {
		log.Errorf("sign tx failed: %v", err)
		return nil, err
	}
	if err = txBuilder.SetSignatures(sigV2); err != nil {
		log.Errorf("set signature failed: %v", err)
		return nil, err
	}

	tx := txBuilder.GetTx()
	txBytes, err := txConfig.TxEncoder()(tx)
	if err != nil {
		log.Errorf("encode tx failed: %v", err)
		return nil, err
	}

	serviceClient := sdktx.NewServiceClient(lis.goatGrpcConn)

	txResp, err := serviceClient.BroadcastTx(ctx, &sdktx.BroadcastTxRequest{
		Mode:    sdktx.BroadcastMode_BROADCAST_MODE_SYNC,
		TxBytes: txBytes},
	)
	if err != nil {
		log.Errorf("broadcast tx failed: %v", err)
		return nil, err
	}

	if txResp.TxResponse.Code != 0 {
		log.Errorf("tx response failed: %s", txResp.TxResponse.RawLog)
		return nil, fmt.Errorf("tx response failed, %s", txResp.TxResponse.RawLog)
	}

	hashBytes, err := hex.DecodeString(txResp.TxResponse.TxHash)
	if err != nil {
		log.Errorf("decode tx hash failed: %v", err)
		return nil, err
	}

	// Retry logic: retry querying the transaction up to 5 times with 5 seconds delay between each retry
	maxRetries := 10
	var resultTx *coretypes.ResultTx
	for i := 0; i < maxRetries; i++ {
		resultTx, err = lis.goatRpcClient.Tx(ctx, hashBytes, false)
		if err == nil {
			break
		}
		log.Warnf("query tx failed (attempt %d/%d): %v", i+1, maxRetries, err)
		time.Sleep(2 * time.Second) // Wait for 2 seconds before retrying
	}

	if err != nil {
		log.Errorf("query tx failed after %d attempts: %v", maxRetries, err)
		return nil, err
	}

	// if code = 0, tx success
	if resultTx.TxResult.Code != 0 {
		log.Warnf("submit tx to consensus error: %v", resultTx.TxResult)
	}
	return resultTx, nil
}

func (lis *Layer2Listener) convertToTypes(msg interface{}) (*bitcointypes.MsgNewDeposits, *bitcointypes.MsgNewBlockHashes, error) {
	if msgNewDeposits, ok := msg.(*bitcointypes.MsgNewDeposits); ok {
		return msgNewDeposits, nil, nil
	}
	if msgNewBlockHashes, ok := msg.(*bitcointypes.MsgNewBlockHashes); ok {
		return nil, msgNewBlockHashes, nil
	}
	return nil, nil, errors.New("type assertion failed: not type MsgNewDeposits or MsgNewBlockHashes")
}
