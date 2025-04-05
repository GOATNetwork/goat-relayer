package layer2

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	goattypes "github.com/goatnetwork/goat/x/goat/types"
	log "github.com/sirupsen/logrus"
)

func (lis *Layer2Listener) processGethEvent(ctx context.Context, block uint64, event abcitypes.Event) error {
	switch event.Type {
	case goattypes.EventTypeNewEthBlock:
		return lis.processNewEthBlock(ctx, block, event.Attributes)

	default:
		return nil
	}
}

func (lis *Layer2Listener) handleFundsReceived(taskId *big.Int, fundingTxHash []byte, txOut uint64) error {
	// TODO: handle funds received event

	lis.state.UpdateSafeboxTask(taskId.Uint64(), fundingTxHash, txOut)
	return nil
}

// Handle TaskCreated event
func (lis *Layer2Listener) handleTaskCreated(taskId *big.Int) error {
	task, err := lis.contractTaskManager.Tasks(nil, taskId)
	if err != nil {
		return fmt.Errorf("failed to get task info: %v", err)
	}

	log.WithFields(log.Fields{
		"taskId":          taskId,
		"timelockEndTime": time.Unix(int64(task.TimelockEndTime), 0),
		"deadline":        time.Unix(int64(task.Deadline), 0),
		"amount":          task.Amount,
		"btcAddress":      task.BtcAddress,
		"depositAddress":  task.DepositAddress,
		"partnerId":       task.PartnerId,
	}).Info("new task created")

	// NOTE: contract task amount decimal is 18, but UTXO amount decimal is 8
	amount := new(big.Int).Div(task.Amount, big.NewInt(1e10))
	lis.state.CreateSafeboxTask(taskId.Uint64(), task.PartnerId.String(), uint64(task.TimelockEndTime), uint64(task.Deadline), amount.Uint64(), task.DepositAddress.Hex(), hex.EncodeToString(task.BtcAddress[:]))

	return nil
}
