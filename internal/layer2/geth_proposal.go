package layer2

import (
	"context"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/goatnetwork/tss/pkg/crypto"
)

// GethProposal handles proposals for Ethereum contract calls
type GethProposal struct {
	client     *ethclient.Client
	rpcClient  *rpc.Client
	chainID    *big.Int
	fromAddr   common.Address
	maxRetries int
}

// NewGethProposal creates a new GethProposal instance
func NewGethProposal(rpcURL string, chainID *big.Int, fromAddr common.Address) (*GethProposal, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, err
	}

	rpcClient, err := rpc.Dial(rpcURL)
	if err != nil {
		return nil, err
	}

	return &GethProposal{
		client:     client,
		rpcClient:  rpcClient,
		chainID:    chainID,
		fromAddr:   fromAddr,
		maxRetries: 3,
	}, nil
}

// UnsignedTx represents an unsigned transaction information
type UnsignedTx struct {
	Tx          *types.Transaction
	MessageHash []byte
}

// CreateUnsignedTx creates an unsigned transaction
func (p *GethProposal) CreateUnsignedTx(ctx context.Context, to common.Address, data []byte, value *big.Int) (*UnsignedTx, error) {
	var err error
	var nonce uint64
	var gasLimit uint64
	var baseFee *big.Int
	var tip *big.Int

	// Get nonce
	for i := 0; i < p.maxRetries; i++ {
		nonce, err = p.client.PendingNonceAt(ctx, p.fromAddr)
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return nil, err
	}

	// Get gas price
	block, err := p.client.BlockByNumber(ctx, nil)
	if err != nil {
		return nil, err
	}
	baseFee = block.BaseFee()
	tip = big.NewInt(5000000) // Can be adjusted as needed
	maxFeePerGas := new(big.Int).Add(baseFee, tip)

	// Estimate gas limit
	msg := ethereum.CallMsg{
		From:      p.fromAddr,
		To:        &to,
		Data:      data,
		Value:     value,
		GasFeeCap: maxFeePerGas,
		GasTipCap: tip,
	}

	for i := 0; i < p.maxRetries; i++ {
		gasLimit, err = p.client.EstimateGas(ctx, msg)
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return nil, err
	}

	// Create unsigned transaction using methods from tss/pkg/crypto
	unsignTx, messageHash := crypto.CreateEIP1559UnsignTx(
		p.chainID,
		nonce,
		gasLimit,
		&to,
		maxFeePerGas,
		tip,
		value,
		data,
	)

	return &UnsignedTx{
		Tx:          unsignTx,
		MessageHash: messageHash,
	}, nil
}

// Close closes the connections
func (p *GethProposal) Close() {
	if p.client != nil {
		p.client.Close()
	}
	if p.rpcClient != nil {
		p.rpcClient.Close()
	}
}
