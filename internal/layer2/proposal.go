package layer2

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	coretypes "github.com/cometbft/cometbft/rpc/core/types"
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
	log "github.com/sirupsen/logrus"
)

const (
	GoatGasLimit = 300000
)

// Proposal defines a generic structure for handling proposal submissions
type Proposal[T sdk.Msg] struct {
	layer2Listener *Layer2Listener
}

// NewProposal creates a new Proposal instance
func NewProposal[T sdk.Msg](listener *Layer2Listener) *Proposal[T] {
	return &Proposal[T]{
		layer2Listener: listener,
	}
}

// RetrySubmit uses generics to retry submitting proposals to the consensus layer
func (p *Proposal[T]) RetrySubmit(ctx context.Context, requestId string, msg T, retries int) error {
	var err error
	for i := 0; i <= retries; i++ {
		resultTx, err := p.submitToConsensus(ctx, msg)
		if err == nil {
			if resultTx.TxResult.Code != 0 {
				return fmt.Errorf("tx execute error, %v", resultTx.TxResult.Log)
			}
			return nil
		} else if i == retries {
			return err
		}
		log.Warnf("Retrying to submit msg to RPC, attempt %d, request id: %s", i+1, requestId)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second * 2):
		}
	}
	return err
}

func (p *Proposal[T]) submitToConsensus(ctx context.Context, msg T) (*coretypes.ResultTx, error) {
	var err error
	accountPrefix := config.AppConfig.GoatChainAccountPrefix
	chainID := config.AppConfig.GoatChainID
	privKeyStr := config.AppConfig.RelayerPriKey
	denom := config.AppConfig.GoatChainDenom

	p.layer2Listener.goatSdkOnce.Do(func() {
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
	if err := p.layer2Listener.checkAndReconnect(); err != nil {
		log.Errorf("check and reconnect goat client faild: %v", err)
		return nil, err
	}
	privKey := &secp256k1.PrivKey{Key: privKeyBytes}
	address := sdk.AccAddress(privKey.PubKey().Address().Bytes()).String()

	accountReq := &authtypes.QueryAccountRequest{Address: address}
	accountResp, err := p.layer2Listener.goatQueryClient.Account(ctx, accountReq)
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

	err = txBuilder.SetMsgs(msg)
	if err != nil {
		log.Errorf("set msg failed: %v", err)
		return nil, err
	}

	// set fee
	fees := sdk.NewCoins(sdk.NewInt64Coin(denom, 100))
	txBuilder.SetGasLimit(GoatGasLimit)
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

	serviceClient := sdktx.NewServiceClient(p.layer2Listener.goatGrpcConn)

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
		resultTx, err = p.layer2Listener.goatRpcClient.Tx(ctx, hashBytes, false)
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
