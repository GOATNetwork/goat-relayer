package types

import (
	"context"
	"strings"
	"time"

	ethtypes "github.com/ethereum/go-ethereum/core/types"
)

const (
	SIGN_EXPIRED_TIME = 5 * 60

	SIGN_TYPE_SENDORDER_BLS = "SENDORDER:BLS"
	SIGN_TYPE_SENDORDER_TSS = "SENDORDER:TSS"
)

// MsgSignInterface defines the interface for all MsgSign fields
type MsgSignInterface interface {
	CheckExpired() bool
	GetRequestId() string
	GetSigData() []byte
	GetSignType() string
	GetUnsignedTx() *ethtypes.Transaction
	GetSignedTx() *ethtypes.Transaction
	SetSignedTx(tx *ethtypes.Transaction)
}

type MsgSign struct {
	RequestId    string `json:"request_id"`
	Sequence     uint64 `json:"sequence"`
	Epoch        uint64 `json:"epoch"`
	VoterAddress string `json:"voter_address"`
	IsProposer   bool   `json:"is_proposer"`
	SigData      []byte `json:"sig_data"`

	// TssSession related fields
	UnsignedTx *ethtypes.Transaction `json:"unsigned_tx"`
	SignedTx   *ethtypes.Transaction `json:"signed_tx"`

	// SigPk        []byte `json:"sig_pk"`
	CreateTime int64 `json:"create_time"`
}

func (m *MsgSign) CheckExpired() bool {
	return time.Now().Unix() > m.CreateTime+SIGN_EXPIRED_TIME
}

// Implement MsgSignInterface for MsgSign
func (m *MsgSign) GetRequestId() string {
	if m.RequestId == "" {
		return ""
	}
	return m.RequestId
}

func (m *MsgSign) GetSigData() []byte {
	if m.SigData == nil {
		return nil
	}
	return m.SigData
}

func (m *MsgSign) GetSignType() string {
	if strings.HasPrefix(m.RequestId, SIGN_TYPE_SENDORDER_TSS) {
		return SIGN_TYPE_SENDORDER_TSS
	}
	return SIGN_TYPE_SENDORDER_BLS
}

func (m *MsgSign) GetUnsignedTx() *ethtypes.Transaction {
	if m.UnsignedTx == nil {
		return nil
	}
	return m.UnsignedTx
}

func (m *MsgSign) GetSignedTx() *ethtypes.Transaction {
	if m.SignedTx == nil {
		return nil
	}
	return m.SignedTx
}

func (m *MsgSign) SetSignedTx(tx *ethtypes.Transaction) {
	if tx == nil {
		return
	}
	m.SignedTx = tx
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

	Withdraws   []byte   `json:"withdraws"`
	WithdrawIds []uint64 `json:"withdraw_ids"`

	SafeboxTasks []byte   `json:"safebox_tasks"`
	TaskIds      []uint64 `json:"task_ids"`

	WitnessSize uint64 `json:"witness_size"`
}

// MsgSignRbfOrder is used for ReplaceWithdrawalV2 when UTXO conflict is detected
// It references the original Processing ID (Pid) instead of withdrawal IDs
type MsgSignRbfOrder struct {
	MsgSign

	SendOrder []byte `json:"send_order"`
	Utxos     []byte `json:"utxos"`
	Vins      []byte `json:"vins"`
	Vouts     []byte `json:"vouts"`

	// Pid is the Processing ID from the original ProcessWithdrawalV2
	Pid uint64 `json:"pid"`
	// WithdrawIds are the original withdrawal IDs (for reference, not for signature)
	WithdrawIds []uint64 `json:"withdraw_ids"`
	// NewTxFee is the new (higher) transaction fee
	NewTxFee uint64 `json:"new_tx_fee"`
	// WitnessSize is the witness data size
	WitnessSize uint64 `json:"witness_size"`
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

type MsgSignSafeboxTask struct {
	MsgSign

	SafeboxTask []byte `json:"safebox_task"`
}

// Deprecated: TssSession defines the tss session for contract call
type TssSession struct {
	TaskId uint64 `json:"task_id"` // task id from db

	SessionId     string                `json:"session_id"`
	SignExpiredTs int64                 `json:"sign_expired_ts"`
	MessageToSign []byte                `json:"message_to_sign"`
	UnsignedTx    *ethtypes.Transaction `json:"unsigned_tx"`

	Status           string `json:"status"`
	Amount           uint64 `json:"amount"`
	DepositAddress   string `json:"deposit_address"`
	TimelockEndTime  uint64 `json:"timelock_end_time"`
	Pubkey           []byte `json:"pubkey"`
	FundingTxid      string `json:"funding_txid"`
	FundingOutIndex  uint64 `json:"funding_out_index"`
	TimelockTxid     string `json:"timelock_txid"`
	TimelockOutIndex uint64 `json:"timelock_out_index"`

	SignedTx *ethtypes.Transaction `json:"signed_tx"`
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
