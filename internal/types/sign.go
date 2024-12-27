package types

import "context"

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

type MsgSignDeposit struct {
	MsgSign
	Deposits      []MsgDeposit     `json:"deposits"`
	BlockHeaders  []MsgBlockHeader `json:"block_headers"`
	RelayerPubkey []byte           `json:"relayer_pubkey"`
	Proposer      string           `json:"proposer"`
}

type MsgDeposit struct {
	Version           uint32 `json:"version,omitempty"`
	BlockNumber       uint64 `json:"block_number"`
	TxHash            []byte `json:"tx_hash"`
	TxIndex           uint32 `json:"tx_index"`
	IntermediateProof []byte `json:"intermediate_proof"`
	MerkleRoot        []byte `json:"merkle_root"`
	NoWitnessTx       []byte `json:"no_witness_tx,omitempty"`
	OutputIndex       int    `json:"output_index"`
	EvmAddress        []byte `json:"evm_address"`
}

type MsgBlockHeader struct {
	Raw    []byte `json:"raw"`
	Height uint64 `json:"height"`
}

// MsgSignSendOrder is used to sign send order, contains withdraw and consolidation
type MsgSignSendOrder struct {
	MsgSign

	SendOrder []byte `json:"send_order"`
	Utxos     []byte `json:"utxos"`
	Vins      []byte `json:"vins"`
	Vouts     []byte `json:"vouts"`
	Withdraws []byte `json:"withdraws"`

	WithdrawIds []uint64 `json:"withdraw_ids"`
}

type MsgSignFinalizeWithdraw struct {
	MsgSign

	Pid               uint64 `json:"pid"`
	Txid              []byte `json:"txid"`
	TxIndex           uint32 `json:"tx_index"`
	BlockNumber       uint64 `json:"block_number"`
	BlockHeader       []byte `json:"block_header"`
	IntermediateProof []byte `json:"intermediate_proof"`
}

type MsgSignReplaceWithdraw struct {
	MsgSign

	Pid            uint64 `json:"pid"`
	NewNoWitnessTx []byte `json:"new_no_witness_tx"`
	NewTxFee       uint64 `json:"new_tx_fee"`
}

type MsgSignCancelWithdraw struct {
	MsgSign

	WithdrawIds []uint64 `json:"withdraw_ids"`
}

type MsgSignNewVoter struct {
	MsgSign

	Proposer         string `json:"proposer"`
	VoterBlsKey      []byte `json:"voter_bls_key"`
	VoterTxKey       []byte `json:"voter_tx_key"`
	VoterTxKeyProof  []byte `json:"voter_tx_key_proof"`
	VoterBlsKeyProof []byte `json:"voter_bls_key_proof"`
}

// BlsSignProcessor defines the interface for the BLS signature processor
type BlsSignProcessor interface {
	BeginSig()
	HandleSigFinish(msgSign interface{})
	HandleSigFailed(msgSign interface{})
	HandleSigTimeout(msgSign interface{})

	Start(ctx context.Context)
	Stop()
}
