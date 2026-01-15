package p2p

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/goatnetwork/goat-relayer/internal/types"
)

func PublishMessage(ctx context.Context, msg any) error {
	return libp2pNetwork.BroadcastMessage(msg)
}

func unmarshal[T any](data json.RawMessage) T {
	var obj T
	err := json.Unmarshal(data, &obj)
	if err != nil || data == nil {
		panic(fmt.Errorf("unmarshal data:%v, error: %w", data, err))
	}
	return obj
}

// convertMsgData converts the message data to the corresponding struct
func convertMsgData(msg Message[json.RawMessage]) any {
	switch msg.DataType {
	case "MsgSignNewBlock":
		return unmarshal[types.MsgSignNewBlock](msg.Data)
	case "MsgUtxoDeposit":
		return unmarshal[types.MsgUtxoDeposit](msg.Data)
	case "MsgSignSendOrder":
		return unmarshal[types.MsgSignSendOrder](msg.Data)
	case "MsgSendOrderBroadcasted":
		return unmarshal[types.MsgSendOrderBroadcasted](msg.Data)
	case "MsgSignNewVoter":
		return unmarshal[types.MsgSignNewVoter](msg.Data)
	case "MsgSafeboxTask":
		return unmarshal[types.MsgSignSafeboxTask](msg.Data)
	case "MsgSendOrderRbf":
		return unmarshal[types.MsgSendOrderRbf](msg.Data)
	}
	return unmarshal[any](msg.Data)
}
