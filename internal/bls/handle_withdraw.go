// handle_wallet.go handle wallet send order bls sig
// contains withdrawal and consolidation
package bls

import (
	"context"
	"fmt"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/p2p"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/goatnetwork/goat-relayer/internal/types"
	bitcointypes "github.com/goatnetwork/goat/x/bitcoin/types"
	log "github.com/sirupsen/logrus"
)

// handleSigStartWithdrawFinalize handle start withdraw finalize sig event
func (s *Signer) handleSigStartWithdrawFinalize(ctx context.Context, e types.MsgSignFinalizeWithdraw) error {
	canSign := s.CanSign()
	isProposer := s.IsProposer()
	if !canSign || !isProposer {
		log.Debugf("Ignore SigStart SendOrder request id %s, canSign: %v, isProposer: %v", e.RequestId, canSign, isProposer)
		log.Debugf("Current l2 context, catching up: %v, self address: %s, proposer: %s", s.state.GetL2Info().Syncing, s.address, s.state.GetEpochVoter().Proposer)
		return fmt.Errorf("cannot start sig %s in current l2 context, catching up: %v, is proposer: %v", e.RequestId, !canSign, isProposer)
	}

	// request id format: SENDORDER:VoterAddr:OrderId
	// check map
	_, ok := s.sigExists(e.RequestId)
	if ok {
		return fmt.Errorf("sig send order exists: %s", e.RequestId)
	}

	// build sign
	rpcMsg := &bitcointypes.MsgFinalizeWithdrawal{
		Proposer:          e.MsgSign.VoterAddress,
		Pid:               e.Pid,
		Txid:              e.Txid,
		BlockNumber:       e.BlockNumber,
		TxIndex:           e.TxIndex,
		IntermediateProof: e.IntermediateProof,
		BlockHeader:       e.BlockHeader,
	}
	err := s.RetrySubmit(ctx, e.RequestId, rpcMsg, config.AppConfig.L2SubmitRetry)
	if err != nil {
		log.Errorf("Proposer submit FinalizeWithdrawal to consensus error, request id: %s, err: %v", e.RequestId, err)
		// feedback SigFailed, deposit should module subscribe it to save UTXO or mark confirm
		s.state.EventBus.Publish(state.SigFailed, e)
		return err
	}
	s.removeSigMap(e.RequestId, false)

	// p2p broadcast
	p2pMsg := p2p.Message[any]{
		MessageType: p2p.MessageTypeWithdrawFinalize,
		RequestId:   e.RequestId,
		DataType:    "MsgSignFinalizeWithdraw",
		Data:        *rpcMsg,
	}
	if err := p2p.PublishMessage(ctx, p2pMsg); err != nil {
		log.Errorf("SigStart public MsgSignSendOrder to p2p error, request id: %s, err: %v", e.RequestId, err)
		return err
	}

	return nil
}
