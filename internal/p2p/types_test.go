package p2p

import (
	"encoding/json"
	"github.com/goatnetwork/goat-relayer/internal/types"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMsgDecode(t *testing.T) {
	originMsg := Message[any]{
		MessageType: 10,
		RequestId:   "test",
		DataType:    "test",
		Data: HeartbeatMessage{
			PeerID:    "100",
			Message:   "test",
			Timestamp: time.Now().Unix(),
		},
	}

	data, err := json.Marshal(originMsg)
	assert.Nil(t, err)
	assert.True(t, len(data) > 0)

	rawMsg := Message[json.RawMessage]{}
	err = json.Unmarshal(data, &rawMsg)
	assert.Nil(t, err)

	heartMsg := HeartbeatMessage{}
	err = json.Unmarshal(rawMsg.Data, &heartMsg)
	assert.Nil(t, err)

	msg := Message[any]{
		MessageType: rawMsg.MessageType,
		RequestId:   rawMsg.RequestId,
		DataType:    rawMsg.DataType,
		Data:        heartMsg,
	}
	assert.Equal(t, originMsg, msg)
}

func TestConvertMsgData(t *testing.T) {
	originMsg := Message[types.MsgSendOrderBroadcasted]{
		MessageType: 10,
		RequestId:   "test",
		DataType:    "MsgSendOrderBroadcasted",
		Data: types.MsgSendOrderBroadcasted{
			TxId:         "1000",
			ExternalTxId: "200",
		},
	}

	data, err := json.Marshal(originMsg)
	assert.Nil(t, err)
	assert.True(t, len(data) > 0)

	rawMsg := Message[json.RawMessage]{}
	err = json.Unmarshal(data, &rawMsg)
	assert.Nil(t, err)

	event := convertMsgData(rawMsg)
	orderMag, ok := event.(types.MsgSendOrderBroadcasted)
	assert.True(t, ok)

	msg := Message[types.MsgSendOrderBroadcasted]{
		MessageType: rawMsg.MessageType,
		RequestId:   rawMsg.RequestId,
		DataType:    rawMsg.DataType,
		Data:        orderMag,
	}
	t.Log("msg", msg)
	assert.Equal(t, originMsg, msg)
}
