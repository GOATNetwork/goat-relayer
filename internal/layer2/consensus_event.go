package layer2

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/db"

	"github.com/ethereum/go-ethereum/common"
	log "github.com/sirupsen/logrus"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	bitcointypes "github.com/goatnetwork/goat/x/bitcoin/types"
	relayertypes "github.com/goatnetwork/goat/x/relayer/types"
)

func (lis *Layer2Listener) processEvent(block uint64, event abcitypes.Event) error {
	switch event.Type {
	case relayertypes.EventTypeNewEpoch:
		return lis.processNewEpochEvent(block, event.Attributes)
	case relayertypes.EventFinalizedProposal:
		return lis.processFinalizedProposalEvent(block, event.Attributes)
	case relayertypes.EventElectedProposer:
		return lis.processElectedProposerEvent(block, event.Attributes)
	case relayertypes.EventAcceptedProposer:
		return lis.processAcceptedProposerEvent(block, event.Attributes)
	case relayertypes.EventVoterPending, relayertypes.EventVoterOnBoarding, relayertypes.EventVoterBoarded, relayertypes.EventVoterOffBoarding, relayertypes.EventVoterActivated, relayertypes.EventVoterDischarged:
		return lis.processVoterEvent(block, event.Type, event.Attributes)

	case bitcointypes.EventTypeNewBlockHash:
		return lis.processNewBtcBlockHash(block, event.Attributes)
	case bitcointypes.EventTypeNewKey:
		return lis.processNewWalletKey(block, event.Attributes)
	case bitcointypes.EventTypeNewDeposit:
		return lis.processNewDeposit(block, event.Attributes)

	case bitcointypes.EventTypeWithdrawalCancellation:
		return lis.processUserCancelWithdrawal(block, event.Attributes)
	case bitcointypes.EventTypeWithdrawalRequest:
		return lis.processUserRequestWithdrawal(block, event.Attributes)
	case bitcointypes.EventTypeWithdrawalReplace:
		return lis.processUserReplaceWithdrawal(block, event.Attributes)
	case bitcointypes.EventTypeInitializeWithdrawal:
		return lis.processWithdrawalInitialized(block, event.Attributes)
	case bitcointypes.EventTypeApproveCancellation:
		return lis.processWithdrawalCancelApproved(block, event.Attributes)
	case bitcointypes.EventTypeFinalizeWithdrawal:
		return lis.processWithdrawalFinalized(block, event.Attributes)

	default:
		// log.Debugf("Unrecognized event type: %s", event.Type)
		return nil
	}
}

func (lis *Layer2Listener) processChainStatus(latestHeight, l2Confirmations uint64, catchingUp bool) error {
	if err := lis.state.UpdateL2ChainStatus(latestHeight, l2Confirmations, catchingUp); err != nil {
		log.Errorf("Abci process chain status error: %v", err)
		return err
	}
	return nil
}

func (lis *Layer2Listener) processEndBlock(block uint64) error {
	log.Debugf("Abci end block %d", block)
	if err := lis.state.UpdateL2InfoEndBlock(block); err != nil {
		log.Errorf("Abci end block error: %v", err)
		return err
	}
	return nil
}

func (lis *Layer2Listener) processFirstBlock(info *db.L2Info, voters []*db.Voter, epoch, sequence uint64, proposer string, pubkey relayertypes.PublicKey) error {
	err := lis.state.UpdateL2InfoFirstBlock(1, info, voters, epoch, sequence, proposer)
	if err != nil {
		return err
	}
	err = lis.state.UpdateL2InfoLatestBtc(1, info.StartBtcHeight)
	if err != nil {
		return err
	}
	// save pubkey
	walletType := "unknown"
	walletKey := ""
	switch v := pubkey.Key.(type) {
	case *relayertypes.PublicKey_Secp256K1:
		walletType = "secp256k1"
		walletKey = base64.StdEncoding.EncodeToString(v.Secp256K1)
	case *relayertypes.PublicKey_Schnorr:
		walletType = "schnorr"
		walletKey = base64.StdEncoding.EncodeToString(v.Schnorr)
	}
	return lis.state.UpdateL2InfoWallet(1, walletType, walletKey)
}

func (lis *Layer2Listener) processBlockVoters(block uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	respRelayer, err := lis.QueryRelayer(ctx)
	if err != nil {
		return err
	}
	// respVoters, err := lis.QueryVotersOfRelayer(ctx)
	// if err != nil {
	// 	return err
	// }
	voters := []*db.Voter{}
	for _, voterAddress := range respRelayer.Relayer.Voters {
		voters = append(voters, &db.Voter{
			VoteAddr:  voterAddress,
			VoteKey:   "", // hex.EncodeToString(voter.VoteKey)
			Height:    block,
			UpdatedAt: time.Now(),
		})
	}

	err = lis.state.UpdateL2InfoVoters(block, respRelayer.Relayer.Epoch, respRelayer.Sequence, respRelayer.Relayer.Proposer, voters)
	if err != nil {
		log.Errorf("Abci voters update error, %v", err)
	} else {
		log.Debugf("Abci voters update, len %d, addr: %s", len(voters), lis.state.GetEpochVoter().VoteAddrList)
	}
	return err
}

func (lis *Layer2Listener) processUserCancelWithdrawal(block uint64, attributes []abcitypes.EventAttribute) error {
	var id uint64
	for _, attr := range attributes {
		key := attr.Key
		value := attr.Value

		if key == "id" {
			id, _ = strconv.ParseUint(value, 10, 64)
		}
	}
	log.Infof("Abci RequestCancelWithdrawal, block: %d, id: %s", block, id)

	if id == 0 {
		return nil
	}
	return lis.state.UpdateWithdrawCancel(id)
}

func (lis *Layer2Listener) processUserReplaceWithdrawal(block uint64, attributes []abcitypes.EventAttribute) error {
	var id, txPrice uint64
	for _, attr := range attributes {
		key := attr.Key
		value := attr.Value

		if key == "id" {
			id, _ = strconv.ParseUint(value, 10, 64)
		}
		if key == "tx_price" {
			txPrice, _ = strconv.ParseUint(value, 10, 64)
		}
	}
	log.Infof("Abci RequestReplaceWithdrawal, block: %d, id: %d, txPrice: %d", block, id, txPrice)

	if id == 0 {
		return nil
	}
	return lis.state.UpdateWithdrawReplace(id, txPrice)
}

func (lis *Layer2Listener) processUserRequestWithdrawal(block uint64, attributes []abcitypes.EventAttribute) error {
	var address string
	var id, txPrice, amount uint64
	for _, attr := range attributes {
		key := attr.Key
		value := attr.Value

		if key == "id" {
			id, _ = strconv.ParseUint(value, 10, 64)
		}
		if key == "address" {
			address = value
		}
		if key == "tx_price" {
			txPrice, _ = strconv.ParseUint(value, 10, 64)
		}
		if key == "amount" {
			amount, _ = strconv.ParseUint(value, 10, 64)
		}
	}
	log.Infof("Abci RequestWithdrawal, address: %s, block: %d, id: %d, txPrice: %d, amount: %d", address, block, id, txPrice, amount)

	if id == 0 {
		return nil
	}
	return lis.state.CreateWithdrawal(address, block, id, txPrice, amount)
}

func (lis *Layer2Listener) processWithdrawalFinalized(block uint64, attributes []abcitypes.EventAttribute) error {
	var txid string
	for _, attr := range attributes {
		key := attr.Key
		value := attr.Value

		if key == "txid" {
			// BE hash
			txid = value
		}
	}
	log.Infof("Abci FinalizeWithdrawal, block: %d, txid: %s", block, txid)
	if txid == "" {
		return nil
	}
	return lis.state.UpdateWithdrawFinalized(txid)
}

func (lis *Layer2Listener) processWithdrawalCancelApproved(block uint64, attributes []abcitypes.EventAttribute) error {
	var id uint64
	for _, attr := range attributes {
		key := attr.Key
		value := attr.Value

		if key == "id" {
			id, _ = strconv.ParseUint(value, 10, 64)
		}
	}
	log.Infof("Abci ApproveCancelWithdrawal, block: %d, id: %d", block, id)

	if id == 0 {
		return nil
	}

	// NOTE not implement EventTypeApproveCancellation
	return nil
}

func (lis *Layer2Listener) processWithdrawalInitialized(block uint64, attributes []abcitypes.EventAttribute) error {
	var txid string
	for _, attr := range attributes {
		key := attr.Key
		value := attr.Value

		if key == "txid" {
			// BE hash
			txid = value
		}
	}
	log.Infof("Abci NewWithdrawal, block: %d, txid: %s", block, txid)

	if txid == "" {
		return nil
	}
	return lis.state.UpdateWithdrawInitialized(txid)
}

func (lis *Layer2Listener) processNewDeposit(block uint64, attributes []abcitypes.EventAttribute) error {
	var txid string
	var txout uint64
	var address common.Address
	var amount uint64 // NOTE, db use float64
	for _, attr := range attributes {
		key := attr.Key
		value := attr.Value

		if key == "txid" {
			// BE hash
			txid = value
		}
		if key == "txout" {
			txout, _ = strconv.ParseUint(value, 10, 64)
		}
		if key == "address" {
			address = common.HexToAddress(value)
		}
		if key == "amount" {
			amount, _ = strconv.ParseUint(value, 10, 64)
		}
		// TODO goat emit event with block hash, should match deposit with height
		// if key == "block_hash" {
		// 	blockHash = value
		// }
	}

	// TODO should throw error if error occured
	lis.state.UpdateProcessedDeposit(txid)
	lis.state.AddDepositResult(txid, txout, address.Hex(), amount, "")
	log.Infof("Abci NewDeposit, block: %d, txid: %s, txout: %d, address: %v, amount: %d", block, txid, txout, address, amount)

	// TODO
	return nil
}

func (lis *Layer2Listener) processNewWalletKey(block uint64, attributes []abcitypes.EventAttribute) error {
	var walletType string
	var walletKey string
	for _, attr := range attributes {
		key := attr.Key
		value := attr.Value

		if key == "type" {
			walletType = value
		}
		if key == "key" {
			walletKey = value
		}
	}
	log.Infof("Abci NewKey: %s, typ: %s, block: %d", walletKey, walletType, block)
	// update
	if walletKey != "" && walletType != "" {
		err := lis.state.UpdateL2InfoWallet(block, walletType, walletKey)
		if err != nil {
			log.Errorf("Abci processNewWalletKey error: %v", err)
			return err
		}
	}
	return nil
}

func (lis *Layer2Listener) processNewBtcBlockHash(block uint64, attributes []abcitypes.EventAttribute) error {
	var height string
	var hash string
	for _, attr := range attributes {
		key := attr.Key
		value := attr.Value

		if key == "height" {
			height = value
		}
		if key == "hash" {
			// BE hash
			hash = value
		}
	}
	log.Infof("Abci NewBlockHash: %s, block: %d, btcHeight: %s", hash, block, height)

	if height != "" && hash != "" {
		u64, _ := strconv.ParseUint(height, 10, 64)
		err := lis.state.UpdateL2InfoLatestBtc(block, u64)
		if err != nil {
			return err
		}

		// manage BtcHeadState queue
		return lis.state.UpdateProcessedBtcBlock(block, u64, hash)
	}
	return nil
}

// Process new_epoch event
func (lis *Layer2Listener) processNewEpochEvent(block uint64, attributes []abcitypes.EventAttribute) error {
	for _, attr := range attributes {
		key := attr.Key
		value := attr.Value

		if key == "epoch" {
			log.Infof("Abci NewEpoch: %s, block: %d", value, block)

			u64, _ := strconv.ParseUint(value, 10, 64)
			return lis.state.UpdateL2InfoEpoch(block, u64, "")
		}
	}
	return nil
}

// Process finalized_proposal event
func (lis *Layer2Listener) processFinalizedProposalEvent(block uint64, attributes []abcitypes.EventAttribute) error {
	for _, attr := range attributes {
		key := attr.Key
		value := attr.Value

		if key == "sequence" {
			log.Infof("Abci FinalizedProposal Sequence: %s, block: %d", value, block)

			u64, _ := strconv.ParseUint(value, 10, 64)
			return lis.state.UpdateL2InfoSequence(block, u64)
		}
	}
	return nil
}

// Process elected_proposer event
func (lis *Layer2Listener) processElectedProposerEvent(block uint64, attributes []abcitypes.EventAttribute) error {
	var epoch string
	var proposer string

	for _, attr := range attributes {
		key := attr.Key
		value := attr.Value

		switch key {
		case "epoch":
			epoch = value
		case "proposer":
			proposer = value
		}
	}
	log.Infof("Abci ElectedProposer: %s in Epoch: %s, block: %d", proposer, epoch, block)

	// query and update voters
	err := lis.processBlockVoters(block)
	if err != nil {
		return err
	}

	u64, _ := strconv.ParseUint(epoch, 10, 64)
	return lis.state.UpdateL2InfoEpoch(block, u64, proposer)
}

// Process accepted_proposer event
func (lis *Layer2Listener) processAcceptedProposerEvent(block uint64, attributes []abcitypes.EventAttribute) error {
	for _, attr := range attributes {
		key := attr.Key
		value := attr.Value

		if key == "proposer" {
			log.Infof("Abci AcceptedProposer: %s, block: %d", value, block)
		}
	}
	// Not save this event yet
	return nil
}

// Voter events
func (lis *Layer2Listener) processVoterEvent(block uint64, eventType string, attributes []abcitypes.EventAttribute) error {
	for _, attr := range attributes {
		key := attr.Key
		value := attr.Value

		log.Infof("Abci %s - %s: %s, block: %d", eventType, key, value, block)

		// The value is addrStr, from goat.
		// addrRaw := sdktypes.AccAddress(goatcrypto.Hash160Sum(req.VoterTxKey))
		// addrStr, err := k.AddrCodec.BytesToString(addrRaw)
		// Relayer voter should calculate from secp256k1 private key,
		// then derive the public key, convert pk to address

		// means next epoch valid
		// if key == "voter_pending" {
		// }

		if key == "voter_on_boarding" {
			// TODO should pass event, notify voter to accept boarding
			// Call event bus, send block, voterAddr
			// Push state queue
		}

		if key == "voter_boarded" {
			// TODO should pass event, notify voter to mark boarded
			// Call event bus, send block, voterAddr
			// Update state queue status

			// TODO query voter
		}

		if key == "voter_activated" {
			// TODO should pass event, notify voter to add to list
			// Call event bus, send block, voterAddr
			// Update state status (state -> db)
		}

		if key == "voter_discharged" {
			// TODO should pass event, notify voter to remove from list
			// Call event bus, send block, voterAddr
			// Update state status (state -> db)
		}
	}
	return nil
}
