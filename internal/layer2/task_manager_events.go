package layer2

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	log "github.com/sirupsen/logrus"
)

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
