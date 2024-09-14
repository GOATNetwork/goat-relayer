package p2p

type Message struct {
	MessageType MessageType `json:"msg_type"`
	RequestId   string      `json:"request_id"`
	DataType    string      `json:"data_type"`
	Data        interface{} `json:"data"`
}

type HeartbeatMessage struct {
	PeerID    string `json:"peer_id"`
	Message   string `json:"message"`
	Timestamp int64  `json:"ts"`
}

type MessageType int

const (
	MessageTypeUnknown MessageType = iota
	MessageTypeSigReq
	MessageTypeSigResp
	MessageTypeDepositReceive
)
