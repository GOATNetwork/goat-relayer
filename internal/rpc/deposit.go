package rpc

// TODO: Query Height by TxHash 1 time(10 min
// Query Tx at BtcCache(db.BtcCache) -> ConfirmedChannel (TxHash + MsgTx + EvmAddress + BlockHeight + BlockHash)

// TODO: BtcLight(db.BtcBlock) 6 times ( 1 hour )
// SPV Generate, Combine MsgNewDeposits{Header, Deposit} -> eventbus(SigStart)
