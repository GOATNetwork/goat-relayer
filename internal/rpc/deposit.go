package rpc

// TODO: Query Height by TxHash 1 time(10 min
// Query Tx at BtcCache(db.BtcCache) -> ConfirmedChannel (TxHash + MsgTx + EvmAddress + BlockHeight + BlockHash)

// TODO: BtcLight(db.BtcBlock) 6 times ( 1 hour )
// SPV Generate, Combine MsgNewDeposits{Header, Deposit} -> eventbus(SigStart)

// TODO: RECEIVE deposit from eventbus (come from p2p other nodes), this deposit module get it and save to db after confirm it is onchain or in deposit table

// TODO subscribe eventbus SigFinish|SigFailed, then do more (retry? mark ok?)

// TODO subscribe eventbus DepositReceive, save it to db as rpc (check existing)
