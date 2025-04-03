package db

const (
	BTC_BLOCK_STATUS_UNCONFIRM = "unconfirm"
	BTC_BLOCK_STATUS_CONFIRMED = "confirmed"
	BTC_BLOCK_STATUS_SIGNING   = "signing"
	BTC_BLOCK_STATUS_PENDING   = "pending"
	BTC_BLOCK_STATUS_PROCESSED = "processed"

	WALLET_TYPE_P2WPKH  = "P2WPKH"
	WALLET_TYPE_P2PKH   = "P2PKH"
	WALLET_TYPE_P2SH    = "P2SH"
	WALLET_TYPE_P2WSH   = "P2WSH"
	WALLET_TYPE_P2TR    = "P2TR"
	WALLET_TYPE_UNKNOWN = "UNKNOWN"

	ORDER_TYPE_WITHDRAWAL    = "withdrawal"
	ORDER_TYPE_CONSOLIDATION = "consolidation"
	ORDER_TYPE_SAFEBOX       = "safebox"
	ORDER_STATUS_AGGREGATING = "aggregating"
	ORDER_STATUS_INIT        = "init"
	ORDER_STATUS_PENDING     = "pending"
	ORDER_STATUS_RBF_REQUEST = "rbf-request"
	ORDER_STATUS_UNCONFIRM   = "unconfirm"
	ORDER_STATUS_CONFIRMED   = "confirmed"
	ORDER_STATUS_PROCESSED   = "processed"
	ORDER_STATUS_CLOSED      = "closed"

	WITHDRAW_STATUS_CREATE      = "create"
	WITHDRAW_STATUS_AGGREGATING = "aggregating"
	WITHDRAW_STATUS_INIT        = "init"
	WITHDRAW_STATUS_SIGNING     = "signing"
	WITHDRAW_STATUS_PENDING     = "pending"
	WITHDRAW_STATUS_UNCONFIRM   = "unconfirm"
	WITHDRAW_STATUS_CONFIRMED   = "confirmed"
	WITHDRAW_STATUS_CANCELING   = "canceling"
	WITHDRAW_STATUS_PROCESSED   = "processed"
	WITHDRAW_STATUS_CLOSED      = "closed"

	UTXO_STATUS_UNCONFIRM = "unconfirm"
	UTXO_STATUS_CONFIRMED = "confirmed"
	UTXO_STATUS_PROCESSED = "processed"
	UTXO_STATUS_PENDING   = "pending"
	UTXO_STATUS_SPENT     = "spent"

	UTXO_SOURCE_DEPOSIT       = "deposit"
	UTXO_SOURCE_WITHDRAWAL    = "withdrawal" // change to withdrawal
	UTXO_SOURCE_CONSOLIDATION = "consolidation"
	UTXO_SOURCE_UNKNOWN       = "unknown"

	DEPOSIT_STATUS_UNCONFIRM = "unconfirm"
	DEPOSIT_STATUS_CONFIRMED = "confirmed"
	DEPOSIT_STATUS_SIGNING   = "signing"
	DEPOSIT_STATUS_PENDING   = "pending"
	DEPOSIT_STATUS_PROCESSED = "processed"

	TASK_STATUS_CREATE      = "create"
	TASK_STATUS_RECEIVED    = "received"
	TASK_STATUS_RECEIVED_OK = "received_ok" // this status means contract task is received after BTC deposit and tss signed TX submit to goat success
	TASK_STATUS_AGGREGATING = "aggregating"
	TASK_STATUS_INIT        = "init"
	TASK_STATUS_SIGNING     = "signing"
	TASK_STATUS_PENDING     = "pending"
	TASK_STATUS_CONFIRMED   = "confirmed"
	TASK_STATUS_PROCESSED   = "processed"
	TASK_STATUS_COMPLETED   = "completed"
	TASK_STATUS_CLOSED      = "closed"
)
