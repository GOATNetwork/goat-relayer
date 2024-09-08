package layer2

import (
	"context"

	"github.com/goatnetwork/goat-relayer/internal/bls"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/p2p"
	"github.com/goatnetwork/goat-relayer/internal/state"
	bitcointypes "github.com/goatnetwork/goat/x/bitcoin/types"
	relayertypes "github.com/goatnetwork/goat/x/relayer/types"
	"github.com/kelindar/bitmap"
)

type Proposal struct {
	state     *state.State
	blsHelper *bls.SignatureHelper
}

func NewProposal(state *state.State, blsHelper *bls.SignatureHelper, p2pService *p2p.LibP2PService) *Proposal {
	p := &Proposal{
		state:     state,
		blsHelper: blsHelper,
	}
	return p
}

func (p *Proposal) Start(ctx context.Context) {
	go p.handleBtcBlocks(ctx)
}

func (p *Proposal) handleBtcBlocks(ctx context.Context) {
	btcBlockChan := p.state.SubscribeBtcBlocks()
	for {
		select {
		case <-ctx.Done():
			return
		case block := <-btcBlockChan:
			p.handleNewBlock(ctx, block)
		}
	}
}

func (p *Proposal) handleNewBlock(ctx context.Context, block *db.BtcBlock) {
	voters := make(bitmap.Bitmap, 256)

	votes := &relayertypes.Votes{
		Sequence:  0,
		Epoch:     0,
		Voters:    voters.ToBytes(),
		Signature: nil,
	}

	msgBlock := bitcointypes.MsgNewBlockHashes{
		Proposer:         "",
		Vote:             votes,
		StartBlockNumber: block.Height,
		BlockHash:        [][]byte{[]byte(block.Hash)},
	}

	signature := p.blsHelper.SignDoc(ctx, msgBlock.VoteSigDoc())

	votes.Signature = signature.Compress()
	msgBlock.Vote = votes

	p.submitToConsensus(ctx, &msgBlock)
}

func (p *Proposal) submitToConsensus(ctx context.Context, msg *bitcointypes.MsgNewBlockHashes) {
	// todo
}
