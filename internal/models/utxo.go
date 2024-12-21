package models

import (
	"time"
)

// Utxo model (wallet UTXO)
type Utxo struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	Uid           string    `gorm:"not null" json:"uid"`
	Txid          string    `gorm:"not null;index:unique_txid_out_index,unique" json:"txid"`
	PkScript      []byte    `json:"pk_script"`
	SubScript     []byte    `json:"sub_script"`
	OutIndex      int       `gorm:"not null;index:unique_txid_out_index,unique" json:"out_index"`
	Amount        int64     `gorm:"not null;index:utxo_amount_index" json:"amount"`
	Receiver      string    `gorm:"not null;index:utxo_receiver_index" json:"receiver"`
	WalletVersion string    `gorm:"not null" json:"wallet_vesion"`
	Sender        string    `gorm:"not null" json:"sender"`
	EvmAddr       string    `json:"evm_addr"`
	Source        string    `gorm:"not null" json:"source"`
	ReceiverType  string    `gorm:"not null" json:"receiver_type"`
	Status        string    `gorm:"not null" json:"status"`
	ReceiveBlock  uint64    `gorm:"not null" json:"receive_block"`
	SpentBlock    uint64    `gorm:"not null" json:"spent_block"`
	UpdatedAt     time.Time `gorm:"not null" json:"updated_at"`
}
