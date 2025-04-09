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
	// handle funds received event
	log.WithFields(log.Fields{
		"taskId": taskId,
		"txHash": fundingTxHash,
		"txOut":  txOut,
	}).Info("Layer2Listener handleFundsReceived - Retrieved funding transaction")

	err := lis.state.UpdateSafeboxTaskReceivedOK(taskId.Uint64(), fundingTxHash, txOut)
	if err != nil {
		log.Errorf("Layer2Listener handleFundsReceived - Failed to update safebox task: %v", err)
		return err
	}

	log.Infof("Layer2Listener handleFundsReceived - Successfully updated safebox task for taskId: %v", taskId)
	return nil
}

// Handle TaskCreated event
func (lis *Layer2Listener) handleTaskCreated(ctx context.Context, taskId *big.Int) error {
	log.Infof("Layer2Listener handleTaskCreated - Event for taskId: %v", taskId)

	callOpts := &bind.CallOpts{
		Context: ctx,
	}

	task, err := lis.contractTaskManager.GetTask(callOpts, taskId)
	if err != nil {
		log.Errorf("Layer2Listener handleTaskCreated - Failed to get task info for taskId %v: %v", taskId, err)
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
	}).Info("Layer2Listener handleTaskCreated - Retrieved task details")

	// NOTE: contract task amount decimal is 18, but UTXO amount decimal is 8
	amount := new(big.Int).Div(task.Amount, big.NewInt(1e10))
	log.Infof("Layer2Listener handleTaskCreated - Converted amount from contract decimal (18) to UTXO decimal (8): %v", amount)

	btcAddress := make([]byte, len(task.BtcAddress[0])+len(task.BtcAddress[1]))
	copy(btcAddress, task.BtcAddress[0][:])
	copy(btcAddress[len(task.BtcAddress[0]):], task.BtcAddress[1][:])
	log.Infof("Layer2Listener handleTaskCreated - Constructed BTC address from parts: %s", hex.EncodeToString(btcAddress))

	pubkey := make([]byte, 33)
	copy(pubkey, task.BtcPubKey[0][:])
	pubkey[32] = task.BtcPubKey[1][0]
	log.Infof("Layer2Listener handleTaskCreated - Constructed BTC pubkey from parts: %s", hex.EncodeToString(pubkey))

	err = lis.state.CreateSafeboxTask(
		taskId.Uint64(),
		task.PartnerId.String(),
		uint64(task.TimelockEndTime),
		uint64(task.Deadline),
		amount.Uint64(),
		task.DepositAddress.Hex(),
		hex.EncodeToString(btcAddress),
		pubkey,
	)
	if err != nil {
		log.Errorf("Layer2Listener handleTaskCreated - Failed to create safebox task: %v", err)
		return err
	}
	log.Infof("Layer2Listener handleTaskCreated - Successfully created safebox task for taskId: %v", taskId)

	return nil
}
