package db

import (
	"time"

	log "github.com/sirupsen/logrus"
)

// L2SyncStatus model
type L2SyncStatus struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	LastSyncBlock uint64    `gorm:"not null" json:"last_sync_block"`
	UpdatedAt     time.Time `gorm:"not null" json:"updated_at"`
}

// L2 Info model (only 1 record)
type L2Info struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	Height          uint64    `gorm:"not null" json:"height"`
	Syncing         bool      `gorm:"not null" json:"syncing"`
	Threshold       string    `json:"threshold"`
	DepositKey      string    `gorm:"not null" json:"deposit_key"` // type,pubKey
	StartBtcHeight  uint64    `gorm:"not null" json:"start_btc_height"`
	LatestBtcHeight uint64    `gorm:"not null" json:"latest_btc_height"`
	UpdatedAt       time.Time `gorm:"not null" json:"updated_at"`
}

// L2 Deposit public key
type DepositPubKey struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	BtcHeight uint64    `gorm:"not null" json:"btc_height"`
	PubType   string    `gorm:"not null" json:"pub_type"`
	PubKey    string    `gorm:"not null" json:"pub_key"`
	UpdatedAt time.Time `gorm:"not null" json:"updated_at"`
}

// Voter model
type Voter struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	VoteAddr  string    `gorm:"not null" json:"vote_addr"`
	VoteKey   string    `gorm:"not null" json:"vote_key"`
	Sequence  uint64    `gorm:"not null" json:"sequence"`
	Height    uint64    `gorm:"not null" json:"height"` // join block height
	UpdatedAt time.Time `gorm:"not null" json:"updated_at"`
}

// EpochVoter model (only 1 record)
type EpochVoter struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	VoteAddrList string    `gorm:"not null" json:"vote_addr_list"`
	VoteKeyList  string    `gorm:"not null" json:"vote_key_list"`
	Epoch        uint64    `gorm:"not null" json:"epoch"`
	Sequence     uint64    `gorm:"not null" json:"sequence"`
	Height       uint64    `gorm:"not null" json:"height"`   // rotate block height
	Proposer     string    `gorm:"not null" json:"proposer"` // proposer address
	UpdatedAt    time.Time `gorm:"not null" json:"updated_at"`
}

// VoterQueue model (for adding/removing voters)
type VoterQueue struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	VoteAddr  string    `gorm:"not null" json:"vote_addr"`
	VoteKey   string    `gorm:"not null" json:"vote_key"`
	Epoch     uint64    `gorm:"not null" json:"epoch"`
	Action    string    `gorm:"not null" json:"action"` // "add" or "remove"
	Status    string    `gorm:"not null" json:"status"` // "init", "pending", "processed"
	UpdatedAt time.Time `gorm:"not null" json:"updated_at"`
}

// BtcBlock model
type BtcBlock struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Height    uint64    `gorm:"not null;uniqueIndex" json:"height"`
	Hash      string    `gorm:"not null" json:"hash"`
	Status    string    `gorm:"not null" json:"status"` // "unconfirm", "confirmed", "signing", "pending", "processed"
	UpdatedAt time.Time `gorm:"not null" json:"updated_at"`
}

// Utxo model (wallet UTXO)
type Utxo struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	Uid           string    `gorm:"not null" json:"uid"`
	Txid          string    `gorm:"not null;index:unique_txid_out_index,unique" json:"txid"`
	PkScript      []byte    `json:"pk_script"`
	OutIndex      int       `gorm:"not null;index:unique_txid_out_index,unique" json:"out_index"`
	Amount        int64     `gorm:"not null" json:"amount"`        // BTC precision up to 8 decimal places
	Receiver      string    `gorm:"not null" json:"receiver"`      // it is MPC address here, or p2wsh (need collect)
	WalletVersion string    `gorm:"not null" json:"wallet_vesion"` // MPC wallet version, it always sets to tss version, "fireblocks:1:2" = fireblocks workspace 1 account 2
	Sender        string    `gorm:"not null" json:"sender"`
	EvmAddr       string    `json:"evm_addr"`                      // deposit to L2
	Source        string    `gorm:"not null" json:"source"`        // "deposit", "unknown"
	ReceiverType  string    `gorm:"not null" json:"receiver_type"` // P2PKH P2SH P2WSH P2WPKH P2TR
	Status        string    `gorm:"not null" json:"status"`        // "unconfirm", "confirmed", "processed", "pending (spend out)", "spent"
	ReceiveBlock  uint64    `gorm:"not null" json:"receive_block"` // recieve at BTC block height
	SpentBlock    uint64    `gorm:"not null" json:"spent_block"`   // spent at BTC block height
	UpdatedAt     time.Time `gorm:"not null" json:"updated_at"`
}

// DepositResult model, it save deposit data from layer2 events
type DepositResult struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	TxId      string `gorm:"uniqueIndex:idx_tx_id_tx_out" json:"tx_id"`
	TxOut     uint64 `gorm:"uniqueIndex:idx_tx_id_tx_out" json:"tx_out"`
	Address   string `gorm:"not null" json:"address"`
	Amount    uint64 `gorm:"not null" json:"amount"`
	BlockHash string `gorm:"not null" json:"block_hash"`
}

// Withdraw model (for managing withdrawals)
type Withdraw struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	EvmTxId   string    `gorm:"not null;uniqueIndex" json:"evm_tx_id"`
	GoatBlock uint64    `gorm:"not null" json:"goat_block"`       // Goat block height
	Amount    float64   `gorm:"type:decimal(20,8)" json:"amount"` // BTC precision up to 8 decimal places
	MaxTxFee  uint      `gorm:"not null" json:"max_tx_fee"`       // Unit is satoshis
	From      string    `gorm:"not null" json:"from"`
	To        string    `gorm:"not null" json:"to"`
	Status    string    `gorm:"not null" json:"status"` // "create", "init", "signing", "pending", "unconfirm", "confirmed", "processed"
	OrderId   string    `json:"order_id"`               // update when signing
	UpdatedAt time.Time `gorm:"not null" json:"updated_at"`
}

// SendOrder model (should send withdraw, vin, vout via off-chain consensus)
type SendOrder struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	OrderId   string    `gorm:"not null;uniqueIndex" json:"order_id"`
	Proposer  string    `gorm:"not null" json:"proposer"`
	Amount    float64   `gorm:"type:decimal(20,8)" json:"amount"` // BTC precision up to 8 decimal places
	MaxTxFee  uint      `gorm:"not null" json:"max_tx_fee"`
	Status    string    `gorm:"not null" json:"status"`                          // "init", "signing", "pending", "rbf-request", "unconfirm", "confirmed", "processed"
	OrderType string    `gorm:"not null" json:"order_type"`                      // "withdrawal", "consolidation"
	BtcBlock  uint64    `gorm:"not null" json:"btc_block"`                       // BTC block height
	Txid      string    `gorm:"not null;index:sendorder_txid_index" json:"txid"` // txid will update after signing status
	UpdatedAt time.Time `gorm:"not null" json:"updated_at"`
}

// Vin model (sent transaction input)
type Vin struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	OrderId   string    `json:"order_id"`
	BtcHeight uint64    `gorm:"not null" json:"btc_height"`
	Txid      string    `gorm:"not null" json:"txid"`
	OutIndex  int       `gorm:"not null" json:"out_index"`
	SigScript []byte    `json:"sig_script"`
	Sender    string    `json:"sender"`
	Source    string    `gorm:"not null" json:"source"` // "withdraw", "unknown"
	Status    string    `gorm:"not null" json:"status"` // "init", "signing", "pending", "unconfirm", "confirmed", "processed"
	UpdatedAt time.Time `gorm:"not null" json:"updated_at"`
}

// Vout model (sent transaction output)
type Vout struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	OrderId    string    `json:"order_id"`
	BtcHeight  uint64    `gorm:"not null" json:"btc_height"`
	Txid       string    `gorm:"not null" json:"txid"`
	OutIndex   int       `gorm:"not null" json:"out_index"`
	WithdrawId string    `json:"withdraw_id"`              // EvmTxId
	Amount     int64     `gorm:"not null" json:"amount"`   // BTC precision up to 8 decimal places
	Receiver   string    `gorm:"not null" json:"receiver"` // withdraw To
	Sender     string    `json:"sender"`                   // MPC address
	Source     string    `gorm:"not null" json:"source"`   // "withdraw", "unknown"
	Status     string    `gorm:"not null" json:"status"`   // "init", "signing", "pending", "unconfirm", "confirmed", "processed"
	UpdatedAt  time.Time `gorm:"not null" json:"updated_at"`
}

// BtcSyncStatus model
type BtcSyncStatus struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	UnconfirmHeight int64     `gorm:"not null" json:"unconfirm_height"`
	ConfirmedHeight int64     `gorm:"not null" json:"confirmed_height"`
	UpdatedAt       time.Time `gorm:"not null" json:"updated_at"`
}

type BtcBlockData struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	BlockHeight  uint64 `gorm:"unique;not null" json:"block_height"`
	BlockHash    string `gorm:"unique;not null" json:"block_hash"`
	Header       []byte `json:"header"`
	Difficulty   uint32 `json:"difficulty"`
	RandomNumber uint32 `json:"random_number"`
	MerkleRoot   string `json:"merkle_root"`
	BlockTime    int64  `json:"block_time"`
	TxHashes     string `json:"tx_hashes"`
}

type BtcTXOutput struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	BlockID  uint   `json:"block_data_id"`
	TxHash   string `json:"tx_hash"`
	Value    uint64 `json:"value"`
	PkScript []byte `json:"pk_script"`
}

// Deposit model (for managing deposits)
type Deposit struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	TxHash      string    `gorm:"not null" json:"tx_hash"`
	RawTx       string    `gorm:"not null" json:"raw_tx"`
	EvmAddr     string    `gorm:"not null" json:"evm_addr"`
	SignVersion uint32    `gorm:"not null" json:"sign_version"`
	Status      string    `gorm:"not null" json:"status"` // "unconfirm", "confirmed", "signing", "pending", "processed"
	UpdatedAt   time.Time `gorm:"not null" json:"updated_at"`
}

type P2WSHInfo struct {
	ID             uint   `gorm:"primaryKey" json:"id"`
	DepositAddress string `gorm:"not null" json:"deposit_address"`
	EvmAddress     string `gorm:"not null" json:"evm_address"`
	TxID           string `gorm:"not null" json:"tx_id"` // transaction id
}

func (dm *DatabaseManager) autoMigrate() {
	if err := dm.l2SyncDb.AutoMigrate(&L2SyncStatus{}); err != nil {
		log.Fatalf("Failed to migrate database 1: %v", err)
	}
	if err := dm.l2InfoDb.AutoMigrate(&L2Info{}, &Voter{}, &EpochVoter{}, &VoterQueue{}, &DepositPubKey{}); err != nil {
		log.Fatalf("Failed to migrate database 2: %v", err)
	}
	if err := dm.btcLightDb.AutoMigrate(&BtcBlock{}); err != nil {
		log.Fatalf("Failed to migrate database 3: %v", err)
	}
	if err := dm.walletDb.AutoMigrate(&Utxo{}, &Withdraw{}, &SendOrder{}, &Vin{}, &Vout{}, &DepositResult{}, &P2WSHInfo{}); err != nil {
		log.Fatalf("Failed to migrate database 4: %v", err)
	}
	if err := dm.btcCacheDb.AutoMigrate(&BtcSyncStatus{}, &BtcBlockData{}, &BtcTXOutput{}, &Deposit{}); err != nil {
		log.Fatalf("Failed to migrate database 5: %v", err)
	}
}
