package bls

import (
	"context"
	"fmt"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"github.com/goatnetwork/goat-relayer/internal/types"
	bitcointypes "github.com/goatnetwork/goat/x/bitcoin/types"
	relayertypes "github.com/goatnetwork/goat/x/relayer/types"
	log "github.com/sirupsen/logrus"
)

func (s *Signer) handleSigStartNewDeposit(ctx context.Context, e types.MsgSignDeposit) error {
	// do not send p2p here, it doesn't need to aggregate sign here
	canSign := s.CanSign()
	isProposer := s.IsProposer()
	if !canSign || !isProposer {
		log.Debugf("Ignore SigStart request id %s, canSign: %v, isProposer: %v", e.RequestId, canSign, isProposer)
		log.Debugf("Current l2 context, catching up: %v, self address: %s, proposer: %s", s.state.GetL2Info().Syncing, s.address, s.state.GetEpochVoter().Proposer)
		return fmt.Errorf("cannot start sig %s in current l2 context, catching up: %v, is proposer: %v", e.RequestId, !canSign, isProposer)
	}

	// request id format: Deposit:VoterAddr:TxHash
	// check map
	_, ok := s.sigExists(e.RequestId)
	if ok {
		return fmt.Errorf("sig exists: %s", e.RequestId)
	}

	newKey := append([]byte{0}, e.RelayerPubkey...)

	pubKey := relayertypes.DecodePublicKey(newKey)
	deposits := make([]*bitcointypes.Deposit, 0)

	for _, tx := range e.DepositTX {
		if bitcointypes.VerifyMerkelProof(tx.TxHash, tx.MerkleRoot, tx.IntermediateProof, uint32(tx.TxIndex)) {
			deposits = append(deposits, &bitcointypes.Deposit{
				Version:           tx.Version,
				BlockNumber:       tx.BlockNumber,
				TxIndex:           tx.TxIndex,
				NoWitnessTx:       tx.NoWitnessTx,
				OutputIndex:       uint32(tx.OutputIndex),
				IntermediateProof: tx.IntermediateProof,
				EvmAddress:        tx.EvmAddress,
				RelayerPubkey:     pubKey,
			})
		}
	}

	rpcMsg := &bitcointypes.MsgNewDeposits{
		Proposer:     e.Proposer,
		BlockHeaders: e.BlockHeader,
		Deposits:     deposits,
	}
	err := s.RetrySubmit(ctx, e.RequestId, rpcMsg, config.AppConfig.L2SubmitRetry)
	if err != nil {
		log.Errorf("Proposer submit NewDeposit to consensus error, request id: %s, err: %v", e.RequestId, err)
		// feedback SigFailed, deposit should module subscribe it to save UTXO or mark confirm
		s.state.EventBus.Publish(state.SigFailed, e)
		return err
	}
	s.removeSigMap(e.RequestId, false)

	// feedback SigFinish, deposit should module subscribe it to save UTXO or mark confirm
	s.state.EventBus.Publish(state.SigFinish, e)
	log.Infof("Proposer submit MsgNewDeposit to consensus ok, request id: %s", e.RequestId)
	return nil
}
