package types

import bitcointypes "github.com/goatnetwork/goat/x/bitcoin/types"

type MsgSign struct {
	RequestId    string `json:"request_id"`
	Sequence     uint64 `json:"sequence"`
	Epoch        uint64 `json:"epoch"`
	VoterAddress string `json:"voter_address"`
	IsProposer   bool   `json:"is_proposer"`
	SigData      []byte `json:"sig_data"`
	// SigPk        []byte `json:"sig_pk"`
	CreateTime int64 `json:"create_time"`
}

type MsgSignNewBlock struct {
	MsgSign

	StartBlockNumber uint64   `json:"start_block_number"`
	BlockHash        [][]byte `json:"block_hash"`
}

// TODO need more fields
type MsgSignDeposit struct {
	MsgSign

	Deposit *bitcointypes.MsgNewDeposits
}
