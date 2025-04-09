package tss

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/goatnetwork/tss/pkg/crypto"
	tssTypes "github.com/goatnetwork/tss/pkg/types"
)

const (
	SignStartPath  = "/api/v1/evm/sign/start"
	SignQueryPath  = "/api/v1/evm/sign/query"
	TssAddressPath = "/api/v1/evm/address"
)

// Signer TSS signer
type Signer struct {
	tssEndpoint string
	httpClient  *http.Client
	chainID     *big.Int
}

// NewSigner creates a new TSS signer
func NewSigner(tssEndpoint string, chainID *big.Int) *Signer {
	return &Signer{
		tssEndpoint: tssEndpoint,
		chainID:     chainID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetTssAddress gets the TSS address
func (s *Signer) GetTssAddress(ctx context.Context) (string, error) {
	resp, err := s.httpClient.Get(s.tssEndpoint + TssAddressPath + "?kdd=1")
	if err != nil {
		return "", fmt.Errorf("get tss address http request failed: %w", err)
	}
	defer resp.Body.Close()

	var tssResp tssTypes.Response[string]
	if err := json.NewDecoder(resp.Body).Decode(&tssResp); err != nil {
		return "", fmt.Errorf("decode response failed: %w", err)
	}

	if tssResp.Status != tssTypes.ResponseStatusSuccess {
		return "", fmt.Errorf("get tss address failed: %v", tssResp.Error)
	}

	return tssResp.Data, nil
}

// QuerySignResult queries the sign result of a session using TSS
// should call ApplySignResult when result.Signature not nil
func (s *Signer) QuerySignResult(ctx context.Context, sessionID string) (*tssTypes.EvmSignQueryResponse, error) {
	resp, err := s.httpClient.Get(s.tssEndpoint + SignQueryPath + "?sessionId=" + sessionID + "&kdd=1")
	if err != nil {
		return nil, fmt.Errorf("query sign result http request failed: %w", err)
	}
	defer resp.Body.Close()

	var signResp tssTypes.Response[tssTypes.EvmSignQueryResponse]
	if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		return nil, fmt.Errorf("decode response failed: %w", err)
	}

	if signResp.Status != tssTypes.ResponseStatusSuccess {
		return nil, fmt.Errorf("query sign result failed: %v", signResp.Error)
	}

	return &signResp.Data, nil
}

// StartSign starts a sign session using TSS
func (s *Signer) StartSign(ctx context.Context, messageHash []byte, sessionID string) (*tssTypes.EvmSignStartResponse, error) {
	req := tssTypes.EvmSignStartRequest{
		Hash:      messageHash,
		SessionID: sessionID,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request failed: %w", err)
	}

	// Add kdd=1 parameter to the URL, same as GetTssAddress
	signURL := s.tssEndpoint + SignStartPath + "?kdd=1"
	resp, err := s.httpClient.Post(signURL, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	var signResp tssTypes.Response[tssTypes.EvmSignStartResponse]
	if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		return nil, fmt.Errorf("decode response failed: %w", err)
	}

	if signResp.Status != tssTypes.ResponseStatusSuccess {
		return nil, fmt.Errorf("start sign failed: %v", signResp.Error)
	}

	return &signResp.Data, nil
}

// StartSignWithUnsignedTx starts a sign session for a transaction using TSS
func (s *Signer) StartSignWithUnsignedTx(ctx context.Context, unsignedTx *types.Transaction, sessionID string) (*tssTypes.EvmSignStartResponse, error) {
	// Get transaction hash
	messageHash := unsignedTx.Hash()

	// Request TSS signature
	resp, err := s.StartSign(ctx, messageHash.Bytes(), sessionID)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// ApplySignResult applies the TSS signature to the unsigned transaction
func (s *Signer) ApplySignResult(ctx context.Context, unsignedTx *types.Transaction, signature *crypto.Signature) (*types.Transaction, error) {
	if signature == nil {
		return nil, fmt.Errorf("tss signature is nil")
	}

	signedTx, err := crypto.SignEIP1559TxWithTss(unsignedTx, s.chainID, signature)
	if err != nil {
		return nil, fmt.Errorf("apply tss sign result failed: %w", err)
	}

	// Debug information: Check the signed transaction
	signer := types.LatestSignerForChainID(s.chainID)
	sender, err := types.Sender(signer, signedTx)
	if err != nil {
		s.logger.Errorf("TssSigner ApplySignResult - ERROR RECOVERING SENDER FROM SIGNED TX: %v", err)
	} else {
		s.logger.Debugf("TssSigner ApplySignResult - SIGNED TX RECOVERED SENDER: %s", sender.Hex())
		s.logger.Debugf("TssSigner ApplySignResult - SIGNED TX HASH: %s", signedTx.Hash().Hex())
		s.logger.Debugf("TssSigner ApplySignResult - SIGNED TX CHAIN ID: %v", signedTx.ChainId())
	}

	return signedTx, nil
}
