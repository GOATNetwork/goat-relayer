package wallet

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/types"

	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/goatnetwork/goat-relayer/internal/state"
	bitcointypes "github.com/goatnetwork/goat/x/bitcoin/types"
	log "github.com/sirupsen/logrus"
)

type DepositProcessor interface {
	Start(ctx context.Context)
	Stop()

	handleDepositSigFailed(event interface{}, reason string)
	handleDepositSigFinish(event interface{})
	initDepositSig()
	checkUnconfirmDeposit()
}

type BaseDepositProcessor struct {
	state     *state.State
	depositCh chan interface{}
	once      sync.Once

	sigDepositMu           sync.Mutex
	sigDepositStatus       bool
	sigDepositFinishHeight uint64

	depositSigFailChan    chan interface{}
	depositSigFinishChan  chan interface{}
	depositSigTimeoutChan chan interface{}

	btcClient     *rpcclient.Client
	nextUnfirmIdx uint64
}

var (
	_ DepositProcessor = (*BaseDepositProcessor)(nil)
)

func NewDepositProcessor(btcClient *rpcclient.Client, state *state.State) DepositProcessor {
	return &BaseDepositProcessor{
		state:     state,
		btcClient: btcClient,

		depositCh: make(chan interface{}, 100),

		depositSigFailChan:    make(chan interface{}, 10),
		depositSigFinishChan:  make(chan interface{}, 10),
		depositSigTimeoutChan: make(chan interface{}, 10),

		nextUnfirmIdx: 0,
	}
}

func (b *BaseDepositProcessor) Start(ctx context.Context) {
	b.state.EventBus.Subscribe(state.SigFailed, b.depositSigFailChan)
	b.state.EventBus.Subscribe(state.SigFinish, b.depositSigFinishChan)
	b.state.EventBus.Subscribe(state.SigTimeout, b.depositSigTimeoutChan)

	b.state.EventBus.Subscribe(state.DepositReceive, b.depositCh)

	// btc block time is 10 minutes, so we check if there is a deposit to sign every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.Stop()
			return
		case deposit := <-b.depositCh:
			depositData, ok := deposit.(types.MsgUtxoDeposit)
			if !ok {
				log.Errorf("Invalid deposit data type")
				continue
			}
			err := b.state.AddUnconfirmDeposit(depositData.TxId, depositData.RawTx, depositData.EvmAddr, depositData.SignVersion, depositData.OutputIndex, depositData.Amount)
			if err != nil {
				log.Errorf("Failed to add unconfirmed deposit: %v", err)
				continue
			}
		case sigFail := <-b.depositSigFailChan:
			b.handleDepositSigFailed(sigFail, "failed")
		case sigTimeout := <-b.depositSigTimeoutChan:
			b.handleDepositSigFailed(sigTimeout, "timeout")
		case sigFinish := <-b.depositSigFinishChan:
			b.handleDepositSigFinish(sigFinish)
		case <-ticker.C:
			b.initDepositSig()
			b.checkUnconfirmDeposit()
		}
	}
}

func (b *BaseDepositProcessor) Stop() {
	b.state.EventBus.Unsubscribe(state.SigFailed, b.depositSigFailChan)
	b.state.EventBus.Unsubscribe(state.SigFinish, b.depositSigFinishChan)
	b.state.EventBus.Unsubscribe(state.SigTimeout, b.depositSigTimeoutChan)
	b.state.EventBus.Unsubscribe(state.DepositReceive, b.depositCh)

	b.once.Do(func() {
		close(b.depositCh)

		close(b.depositSigFailChan)
		close(b.depositSigFinishChan)
		close(b.depositSigTimeoutChan)
	})

	log.Debug("BaseDepositProcessor Stop")
}

func (b *BaseDepositProcessor) handleDepositSigFailed(event interface{}, reason string) {
	b.sigDepositMu.Lock()
	defer b.sigDepositMu.Unlock()

	if !b.sigDepositStatus {
		log.Debug("Event handleDepositSigFailed ignore, sigDepositStatus is false")
		return
	}

	switch e := event.(type) {
	case types.MsgSignDeposit:
		log.Infof("Event handleDepositSigFailed is of type MsgSignDeposit, request id %s, reason: %s", e.RequestId, reason)
		b.sigDepositStatus = false
	default:
		log.Debug("WalletServer depositLoop ignore unsupport type")
	}
}

func (b *BaseDepositProcessor) handleDepositSigFinish(event interface{}) {
	b.sigDepositMu.Lock()
	defer b.sigDepositMu.Unlock()

	if !b.sigDepositStatus {
		log.Debug("Event handleDepositSigFinish ignore, sigDepositStatus is false")
		return
	}

	switch e := event.(type) {
	case types.MsgSignDeposit:
		log.Infof("Event handleDepositSigFinish is of type MsgSignDeposit, request id %s", e.RequestId)
		b.sigDepositStatus = false
		b.sigDepositFinishHeight = b.state.GetL2Info().Height
	default:
		log.Debug("BaseDepositProcessor depositLoop ignore unsupport type")
	}
}

func (b *BaseDepositProcessor) initDepositSig() {
	log.Debug("BaseDepositProcessor initDepositSig")

	// 1. check catching up, self is proposer
	l2Info := b.state.GetL2Info()
	if l2Info.Syncing {
		log.Debug("BaseDepositProcessor initDepositSig ignore, layer2 is catching up")
		return
	}

	if b.state.GetBtcHead().Syncing {
		log.Debug("BaseDepositProcessor initDepositSig ignore, btc is catching up")
		return
	}

	b.sigDepositMu.Lock()
	defer b.sigDepositMu.Unlock()

	epochVoter := b.state.GetEpochVoter()
	if epochVoter.Proposer != config.AppConfig.RelayerAddress {
		if b.sigDepositStatus && l2Info.Height > epochVoter.Height+1 {
			b.sigDepositStatus = false
		}
		log.Debugf("BaseDepositProcessor initDepositSig ignore, self is not proposer, epoch: %d, proposer: %s", epochVoter.Epoch, epochVoter.Proposer)
		return
	}

	// 2. check if there is a sig in progress
	if b.sigDepositStatus {
		log.Debug("BaseDepositProcessor initDepositSig ignore, there is a sig")
		return
	}
	if l2Info.Height <= b.sigDepositFinishHeight+2 {
		log.Debug("BaseDepositProcessor initDepositSig ignore, last finish sig in 2 blocks")
		return
	}

	// 3. find confirmed deposits for signing
	deposits, err := b.state.GetDepositForSign(16)
	if err != nil {
		log.Errorf("BaseDepositProcessor initDepositSig error: %v", err)
		return
	}
	if len(deposits) == 0 {
		log.Debug("BaseDepositProcessor initDepositSig ignore, no deposit for sign")
		return
	}

	// 4. spv verify
	verifiedBlockHashes := make([]string, 0)
	verifiedDeposits := make([]db.Deposit, 0)
	for _, deposit := range deposits {
		txhash, err := chainhash.NewHashFromStr(deposit.TxHash)
		if err != nil {
			log.Errorf("NewHashFromStr TxHash err: %v", err)
			continue
		}
		txIndex := uint32(deposit.TxIndex)
		if bitcointypes.VerifyMerkelProof(txhash[:], deposit.MerkleRoot, deposit.Proof, txIndex) {
			if !slices.Contains(verifiedBlockHashes, deposit.BlockHash) {
				verifiedBlockHashes = append(verifiedBlockHashes, deposit.BlockHash)
			}
			verifiedDeposits = append(verifiedDeposits, *deposit)
		}
	}

	if len(verifiedBlockHashes) == 0 {
		log.Debug("BaseDepositProcessor initDepositSig ignore, no valid block hash")
		return
	}

	// 5. build sign msg
	pubkey, err := b.state.GetDepositKeyByBtcBlock(0)
	if err != nil {
		log.Fatalf("BaseDepositProcessor get current deposit key by btc height current err %v", err)
	}
	pubkeyBytes, err := base64.StdEncoding.DecodeString(pubkey.PubKey)
	if err != nil {
		log.Fatalf("Base64 decode pubkey %s err %v", pubkey.PubKey, err)
	}

	// 6. get block headers
	blockData, err := b.state.QueryBtcBlockDataByBlockHashes(verifiedBlockHashes)
	if err != nil {
		log.Errorf("QueryBtcBlockDataByBlockHashes error: %v", err)
		return
	}
	msgBlockHeaders := make([]types.MsgBlockHeader, 0)
	for _, blockData := range blockData {
		msgBlockHeaders = append(msgBlockHeaders, types.MsgBlockHeader{
			Raw:    blockData.Header,
			Height: blockData.BlockHeight,
		})
		log.Debugf("WalletServer initDepositSig blockHeaders[%d] %d", blockData.BlockHeight, len(blockData.Header))
	}
	proposer := b.state.GetEpochVoter().Proposer

	requestId := fmt.Sprintf("DEPOSIT:%s:%s", config.AppConfig.RelayerAddress, deposits[0].TxHash)
	msgDeposits := make([]types.MsgDeposit, len(verifiedDeposits))
	for i, verifiedDeposit := range verifiedDeposits {
		txHash, err := chainhash.NewHashFromStr(verifiedDeposit.TxHash)
		if err != nil {
			log.Errorf("NewHashFromStr err: %v", err)
			continue
		}
		evmAddr, err := hex.DecodeString(strings.TrimPrefix(verifiedDeposit.EvmAddr, "0x"))
		if err != nil {
			log.Errorf("DecodeString err: %v", err)
			continue
		}
		rawTx, err := hex.DecodeString(verifiedDeposit.RawTx)
		if err != nil {
			log.Errorf("DecodeString err: %v", err)
			continue
		}
		tx, err := types.DeserializeTransaction(rawTx)
		if err != nil {
			log.Errorf("DeserializeTransaction err: %v", err)
			continue
		}
		noWitnessTx, err := types.SerializeTransactionNoWitness(tx)
		if err != nil {
			log.Errorf("SerializeTransactionNoWitness err: %v", err)
			continue
		}
		msgDeposits[i] = types.MsgDeposit{
			Version:           verifiedDeposit.SignVersion,
			BlockNumber:       verifiedDeposit.BlockHeight,
			TxHash:            txHash.CloneBytes(),
			TxIndex:           uint32(verifiedDeposit.TxIndex),
			NoWitnessTx:       noWitnessTx,
			MerkleRoot:        verifiedDeposit.MerkleRoot,
			OutputIndex:       verifiedDeposit.OutputIndex,
			IntermediateProof: verifiedDeposit.Proof,
			EvmAddress:        evmAddr,
		}
	}
	msgSignDeposit := types.MsgSignDeposit{
		MsgSign: types.MsgSign{
			RequestId: requestId,
		},
		BlockHeaders:  msgBlockHeaders,
		Deposits:      msgDeposits,
		Proposer:      proposer,
		RelayerPubkey: pubkeyBytes,
	}
	b.state.EventBus.Publish(state.SigStart, msgSignDeposit)
	b.sigDepositStatus = true
	log.Infof("P2P publish msgSignDeposit success, request id: %s", requestId)
}

// checkUnconfirmDeposit check if there is any unconfirmed deposit
// 1. only deal with 72 hours unconfirmed deposit
// 2. batch query 50 per time
func (b *BaseDepositProcessor) checkUnconfirmDeposit() {
	deposits, err := b.state.QueryUnConfirmDeposit(b.nextUnfirmIdx, 50)
	if err != nil {
		log.Errorf("QueryUnConfirmDeposit error: %v", err)
		b.nextUnfirmIdx = 0
		return
	}
	if len(deposits) == 0 {
		log.Debugf("BaseDepositProcessor checkUnconfirmDeposit ignore, no deposit unconfirm")
		b.nextUnfirmIdx = 0
		return
	}
	network := types.GetBTCNetwork(config.AppConfig.BTCNetworkType)

	for _, deposit := range deposits {
		if deposit.TxHash == "" || deposit.EvmAddr == "" {
			log.Errorf("Invalid deposit data, txid: %s, evmaddr: %s", deposit.TxHash, deposit.EvmAddr)
			b.nextUnfirmIdx = uint64(deposit.ID)
			continue
		}
		txHash, err := chainhash.NewHashFromStr(deposit.TxHash)
		if err != nil {
			log.Errorf("New hash from str error: %v, raw txid: %s", err, deposit.TxHash)
			continue
		}
		// query btc block data by block hash
		txRawResult, err := b.btcClient.GetRawTransactionVerbose(txHash)
		if err != nil {
			log.Errorf("GetRawTransactionVerbose error: %v", err)
			continue
		}
		if txRawResult.Confirmations < uint64(config.AppConfig.BTCConfirmations) {
			log.Debugf("Tx %s is not enough confirm, confirmations: %d", txRawResult.Txid, txRawResult.Confirmations)
			b.nextUnfirmIdx = uint64(deposit.ID)
			continue
		}
		blockHash, err := chainhash.NewHashFromStr(txRawResult.BlockHash)
		if err != nil {
			log.Errorf("New hash from str error: %v, raw block hash: %s", err, txRawResult.BlockHash)
			continue
		}
		// query block with verbose 2
		block, err := b.btcClient.GetBlockVerboseTx(blockHash)
		if err != nil {
			log.Errorf("Get block verbose error: %v, block hash: %s", err, blockHash.String())
			continue
		}

		// get pubkey
		pubkey, err := b.state.GetDepositKeyByBtcBlock(uint64(block.Height))
		if err != nil {
			log.Fatalf("Get current deposit key by btc height %d err %v", block.Height, err)
		}
		pubkeyBytes, err := base64.StdEncoding.DecodeString(pubkey.PubKey)
		if err != nil {
			log.Fatalf("Base64 decode pubkey %s err %v", pubkey.PubKey, err)
		}
		p2wsh, err := types.GenerateV0P2WSHAddress(pubkeyBytes, deposit.EvmAddr, network)
		if err != nil {
			log.Fatalf("GenerateV0P2WSHAddress err %v", err)
		}

		// just validate v0, v1 will detect by relayer
		isV0, outputIndex, amount, pkScript := types.IsUtxoGoatDepositV0Json(txRawResult, []btcutil.Address{p2wsh}, network)
		if !isV0 {
			log.Errorf("IsUtxoGoatDepositV0Json false, txid: %s", txRawResult.Txid)
			b.nextUnfirmIdx = uint64(deposit.ID)
			continue
		}
		subScript, err := types.BuildSubScriptForP2WSH(deposit.EvmAddr, pubkeyBytes)
		if err != nil {
			log.Errorf("BuildSubScriptForP2WSH err %v", err)
			b.nextUnfirmIdx = uint64(deposit.ID)
			continue
		}

		utxo := &db.Utxo{
			Uid:           "",
			Txid:          txRawResult.Txid,
			PkScript:      pkScript,
			SubScript:     subScript,
			OutIndex:      outputIndex,
			Amount:        amount,
			Receiver:      p2wsh.EncodeAddress(),
			WalletVersion: "1",
			Sender:        "", // don't read sender here
			EvmAddr:       deposit.EvmAddr,
			Source:        db.UTXO_SOURCE_DEPOSIT,
			ReceiverType:  types.WALLET_TYPE_P2WSH,
			Status:        db.UTXO_STATUS_CONFIRMED,
			ReceiveBlock:  uint64(block.Height),
			SpentBlock:    0,
			UpdatedAt:     time.Now(),
		}

		// TODO: not read this record again from db
		msgTx, err := types.ConvertTxRawResultToMsgTx(txRawResult)
		if err != nil {
			log.Errorf("ConvertTxRawResultToMsgTx error: %v", err)
			b.nextUnfirmIdx = uint64(deposit.ID)
			continue
		}

		blockTxHashs := make([]string, 0)
		for _, rawTx := range block.Tx {
			blockTxHashs = append(blockTxHashs, rawTx.Txid)
		}

		noWitnessTx, err := types.SerializeTransactionNoWitness(msgTx)
		if err != nil {
			log.Errorf("SerializeTransactionNoWitness err %v", err)
			b.nextUnfirmIdx = uint64(deposit.ID)
			continue
		}
		merkleRoot, proofBytes, txIndex, err := types.GenerateSPVProof(utxo.Txid, blockTxHashs)
		if err != nil {
			log.Errorf("GenerateSPVProof err %v, txid: %s, block tx hashes: %s", err, utxo.Txid, blockTxHashs)
			b.nextUnfirmIdx = uint64(deposit.ID)
			continue
		}
		err = b.state.AddUtxo(utxo, pubkeyBytes, blockHash.String(), uint64(block.Height), noWitnessTx, merkleRoot, proofBytes, txIndex, true)
		if err != nil {
			log.Fatalf("Add utxo %+v err %v", utxo, err)
		}

		b.nextUnfirmIdx = uint64(deposit.ID)
		log.Infof("Add utxo and deposit tx %s success, tx index: %d, output index: %d", deposit.TxHash, txIndex, deposit.OutputIndex)
	}
}
