package state

import "github.com/goatnetwork/goat-relayer/internal/db"

// VoterState to manage voter-related states
type Layer2State struct {
	CurrentEpoch uint64
	EpochVoter   *db.EpochVoter
	L2Info       *db.L2Info
	Voters       []*db.Voter
	VoterQueue   []*db.VoterQueue
}

// BtcHeadState to manage BTC head
type BtcHeadState struct {
	Latest         db.BtcBlock
	UnconfirmQueue []*db.BtcBlock // status in 'unconfirm', 'confirmed'
	SigQueue       []*db.BtcBlock // status in 'signing', 'pending'
}

// WalletState to manage withdrawal Queue and associated Vin/Vout
type WalletState struct {
	SendOrderQueue []*db.SendOrder
	SentVin        []*db.Vin
	SentVout       []*db.Vout
	Utxo           *db.Utxo
}
