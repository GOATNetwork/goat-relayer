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

// SignRequest TSS signing request
type SignRequest struct {
	MessageHash []byte `json:"message_hash"`
	ChainID     int64  `json:"chain_id"`
}

// SignResponse TSS signing response
type SignResponse struct {
	Signature *crypto.Signature `json:"signature"`
	Success   bool              `json:"success"`
	Error     string            `json:"error,omitempty"`
}

// Sign signs a message using TSS
func (s *Signer) Sign(ctx context.Context, messageHash []byte, chainID int64) (*crypto.Signature, error) {
	req := SignRequest{
		MessageHash: messageHash,
		ChainID:     chainID,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request failed: %w", err)
	}

	resp, err := s.httpClient.Post(s.tssEndpoint+"/sign", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	var signResp SignResponse
	if err := json.NewDecoder(resp.Body).Decode(&signResp); err != nil {
		return nil, fmt.Errorf("decode response failed: %w", err)
	}

	if !signResp.Success {
		return nil, fmt.Errorf("sign failed: %s", signResp.Error)
	}

	return signResp.Signature, nil
}

// SignTx signs a transaction using TSS
func (s *Signer) SignTx(ctx context.Context, tx *types.Transaction) (*types.Transaction, error) {
	// Get transaction hash
	messageHash := tx.Hash()

	// Request TSS signature
	signature, err := s.Sign(ctx, messageHash.Bytes(), s.chainID.Int64())
	if err != nil {
		return nil, fmt.Errorf("tss sign failed: %w", err)
	}

	// Sign transaction using tss/pkg/crypto methods
	signedTx, err := crypto.SignEIP1559TxWithTss(tx, s.chainID, signature)
	if err != nil {
		return nil, fmt.Errorf("sign tx failed: %w", err)
	}

	return signedTx, nil
}
