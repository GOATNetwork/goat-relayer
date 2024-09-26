package wallet

type DepositTransaction struct {
	TxHash      string
	RawTx       string
	EvmAddress  string
	BlockHash   string
	BlockHeight uint64
	BlockHeader []byte
	TxHashList  []string
	SignVersion uint32
}

type DepositInfo struct {
	Tx         DepositTransaction
	MerkleRoot []byte
	Proof      []byte
	TxIndex    uint32
}
