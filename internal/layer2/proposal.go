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
	blsHelper *bls.SignatureHelper
	state     *state.State
}

func NewProposal(state *state.State, blsHelper *bls.SignatureHelper, p2pService *p2p.LibP2PService) *Proposal {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := &Proposal{
		blsHelper: blsHelper,
		state:     state,
	}

	btcHeadChan := make(chan interface{}, 100)
	state.GetEventBus().Subscribe("btcHeadStateUpdated", btcHeadChan)

	go p.handleBtcBlocks(ctx, btcHeadChan)

	return p
}

func (p *Proposal) handleBtcBlocks(ctx context.Context, btcHeadChan chan interface{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-btcHeadChan:
			block, ok := data.(db.BtcBlock)
			if !ok {
				continue
			}
			p.sendTxMsgNewBlockHashes(ctx, &block)
		}
	}
}

func (p *Proposal) sendTxMsgNewBlockHashes(ctx context.Context, block *db.BtcBlock) {
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
	// TODO: integrate consensus tx send
}
