package layer2

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/goatnetwork/goat-relayer/internal/types"
	log "github.com/sirupsen/logrus"
)

func (lis *Layer2Listener) handleBurned(ctx context.Context, taskId *big.Int) error {
	log.Infof("Layer2Listener handleTimelockCompleted - Event for taskId: %v", taskId)

	err := lis.state.UpdateSafeboxTaskCompleted(taskId.Uint64())
	if err != nil {
		log.Errorf("Layer2Listener handleTimelockCompleted - Failed to update safebox task: %v", err)
		return err
	}

	log.Infof("Layer2Listener handleTimelockCompleted - Successfully updated safebox task for taskId: %v", taskId)
	return nil
}

func (lis *Layer2Listener) handleTimelockProcessed(ctx context.Context, taskId *big.Int) error {
	log.Infof("Layer2Listener handleTimelockProcessed - Event for taskId: %v", taskId)

	err := lis.state.UpdateSafeboxTaskProcessed(taskId.Uint64())
	if err != nil {
		log.Errorf("Layer2Listener handleTimelockProcessed - Failed to update safebox task: %v", err)
		return err
	}

	log.Infof("Layer2Listener handleTimelockProcessed - Successfully updated safebox task for taskId: %v", taskId)
	return nil
}

func (lis *Layer2Listener) handleTimelockInitialized(ctx context.Context, taskId *big.Int, timelockTxid []byte, timelockOutIndex uint64) error {
	log.Infof("Layer2Listener handleTimelockInitialized - Event for taskId: %v", taskId)

	timelockTxidStr, err := types.EncodeBtcHash(timelockTxid)
	if err != nil {
		log.Errorf("Layer2Listener handleTimelockInitialized - Failed to encode timelock transaction hash: %v", err)
		return err
	}

	err = lis.state.UpdateSafeboxTaskInitOK(taskId.Uint64(), timelockTxidStr, timelockOutIndex)
	if err != nil {
		log.Errorf("Layer2Listener handleTimelockInitialized - Failed to update safebox task: %v", err)
		return fmt.Errorf("failed to update safebox task: %v", err)
	}

	log.Infof("Layer2Listener handleTimelockInitialized - Successfully updated safebox task for taskId: %v", taskId)
	return nil
}

func (lis *Layer2Listener) handleTaskCancelled(taskId *big.Int) error {
	log.Infof("Layer2Listener handleTaskCancelled - Event for taskId: %v", taskId)

	err := lis.state.UpdateSafeboxTaskCancelled(taskId.Uint64())
	if err != nil {
		log.Errorf("Layer2Listener handleTaskCancelled - Failed to update safebox task: %v", err)
		return err
	}

	log.Infof("Layer2Listener handleTaskCancelled - Successfully updated safebox task for taskId: %v", taskId)
	return nil
}

func (lis *Layer2Listener) handleFundsReceived(taskId *big.Int, fundingTxHash []byte, txOut, timelockEndTime uint64) error {
	// handle funds received event
	log.WithFields(log.Fields{
		"taskId": taskId,
		"txHash": fundingTxHash,
		"txOut":  txOut,
	}).Info("Layer2Listener handleFundsReceived - Retrieved funding transaction")

	fundingTxHashStr, err := types.EncodeBtcHash(fundingTxHash)
	if err != nil {
		log.Errorf("Layer2Listener handleFundsReceived - Failed to encode funding transaction hash: %v", err)
		return err
	}

	err = lis.state.UpdateSafeboxTaskReceivedOK(taskId.Uint64(), fundingTxHashStr, txOut, timelockEndTime)
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

	partnerInfo, err := lis.contractTaskManager.GetPartnerInfo(callOpts, task.PartnerId)
	if err != nil {
		log.Errorf("Layer2Listener handleTaskCreated - Failed to get partner info for partnerId %s: %v", task.PartnerId.String(), err)
		return fmt.Errorf("failed to get partner info: %v", err)
	}

	log.WithFields(log.Fields{
		"taskId":          taskId,
		"timelockEndTime": time.Unix(int64(task.TimelockEndTime), 0),
		"deadline":        time.Unix(int64(task.Deadline), 0),
		"amount":          task.Amount,
		"btcAddress":      partnerInfo.BtcAddress,
		"pubkey":          partnerInfo.BtcPubKey,
		"depositAddress":  task.DepositAddress,
		"partnerId":       task.PartnerId,
	}).Info("Layer2Listener handleTaskCreated - Retrieved task details")

	// NOTE: contract task amount decimal is 18, but UTXO amount decimal is 8
	amount := new(big.Int).Div(task.Amount, big.NewInt(1e10))
	log.Infof("Layer2Listener handleTaskCreated - Converted amount from contract decimal (18) to UTXO decimal (8): %v", amount)

	btcAddress := make([]byte, len(partnerInfo.BtcAddress[0])+len(partnerInfo.BtcAddress[1]))
	copy(btcAddress, partnerInfo.BtcAddress[0][:])
	copy(btcAddress[len(partnerInfo.BtcAddress[0]):], partnerInfo.BtcAddress[1][:])
	log.Infof("Layer2Listener handleTaskCreated - Constructed BTC address from parts: %s", hex.EncodeToString(btcAddress))
	btcRefundAddress := hex.EncodeToString(btcAddress)

	pubkey := make([]byte, 33)
	copy(pubkey, partnerInfo.BtcPubKey[0][:])
	pubkey[32] = partnerInfo.BtcPubKey[1][0]
	log.Infof("Layer2Listener handleTaskCreated - Constructed BTC pubkey from parts: %s", hex.EncodeToString(pubkey))

	// timelockP2WSHAddress, witnessScript, err := types.GenerateTimeLockP2WSHAddress(pubkey, time.Unix(int64(task.TimelockEndTime), 0), types.GetBTCNetwork(config.AppConfig.BTCNetworkType))
	// if err != nil {
	// 	log.Errorf("Layer2Listener handleTaskCreated - Ignore invalid safebox task for generating timelock-P2WSH address from pubkey %s and timelock %d error: %v", pubkey, task.TimelockEndTime, err)
	// 	return nil
	// }
	// timelockAddress := timelockP2WSHAddress.EncodeAddress()

	err = lis.state.CreateSafeboxTask(
		taskId.Uint64(),
		task.PartnerId.String(),
		uint64(task.TimelockEndTime),
		uint64(task.Deadline),
		amount.Uint64(),
		task.DepositAddress.Hex(),
		btcRefundAddress,
		"",
		pubkey,
		nil,
	)
	if err != nil {
		log.Errorf("Layer2Listener handleTaskCreated - Failed to create safebox task: %v", err)
		return err
	}
	log.Infof("Layer2Listener handleTaskCreated - Successfully created safebox task for taskId: %v", taskId)

	return nil
}
