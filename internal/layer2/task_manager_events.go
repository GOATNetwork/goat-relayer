package layer2

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	log "github.com/sirupsen/logrus"
)

func (lis *Layer2Listener) handleFundsReceived(taskId *big.Int, fundingTxHash []byte, txOut uint64) error {
	// TODO: handle funds received event

	lis.state.UpdateSafeboxTask(taskId.Uint64(), fundingTxHash, txOut)
	return nil
}

// Handle TaskCreated event
func (lis *Layer2Listener) handleTaskCreated(ctx context.Context, taskId *big.Int) error {
	log.Infof("Handling TaskCreated event for taskId: %v", taskId)

	callOpts := &bind.CallOpts{
		Context: ctx,
	}

	task, err := lis.contractTaskManager.GetTask(callOpts, taskId)
	if err != nil {
		log.Errorf("Failed to get task info for taskId %v: %v", taskId, err)
		return fmt.Errorf("failed to get task info: %v", err)
	}

	log.WithFields(log.Fields{
		"taskId":          taskId,
		"timelockEndTime": time.Unix(int64(task.TimelockEndTime), 0),
		"deadline":        time.Unix(int64(task.Deadline), 0),
		"amount":          task.Amount,
		"btcAddress":      task.BtcAddress,
		"pubkey":          task.BtcPubKey,
		"depositAddress":  task.DepositAddress,
		"partnerId":       task.PartnerId,
	}).Info("Retrieved task details")

	// NOTE: contract task amount decimal is 18, but UTXO amount decimal is 8
	amount := new(big.Int).Div(task.Amount, big.NewInt(1e10))
	log.Infof("Converted amount from contract decimal (18) to UTXO decimal (8): %v", amount)

	btcAddress := make([]byte, len(task.BtcAddress[0])+len(task.BtcAddress[1]))
	copy(btcAddress, task.BtcAddress[0][:])
	copy(btcAddress[len(task.BtcAddress[0]):], task.BtcAddress[1][:])
	log.Infof("Constructed BTC address from parts: %s", hex.EncodeToString(btcAddress))

	pubkey := make([]byte, len(task.BtcPubKey[0])+len(task.BtcPubKey[1]))
	copy(pubkey, task.BtcPubKey[0][:])
	copy(pubkey[len(task.BtcPubKey[0]):], task.BtcPubKey[1][:])
	log.Infof("Constructed BTC pubkey from parts: %s", hex.EncodeToString(pubkey))

	err = lis.state.CreateSafeboxTask(
		taskId.Uint64(),
		task.PartnerId.String(),
		uint64(task.TimelockEndTime),
		uint64(task.Deadline),
		amount.Uint64(),
		task.DepositAddress.Hex(),
		hex.EncodeToString(btcAddress),
		hex.EncodeToString(pubkey),
	)
	if err != nil {
		log.Errorf("Failed to create safebox task: %v", err)
		return err
	}
	log.Infof("Successfully created safebox task for taskId: %v", taskId)

	return nil
}
