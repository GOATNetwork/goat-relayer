package wallet

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/types"
	log "github.com/sirupsen/logrus"
)

// extract Withdrawal and Consolidation
// vin sender is tss, log vin and vout
func (w *WalletServer) blockScanLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			log.Info("WalletService blockScanLoop stopping...")
			return
		case block := <-w.blockCh:
			btcBlock := block.(types.BtcBlockExt)
			log.Debugf("Btc block wallet module filter, height: %d, hash: %s", btcBlock.BlockNumber, btcBlock.BlockHash().String())

			// get pubkey
			pubkey, err := w.state.GetDepositKeyByBtcBlock(btcBlock.BlockNumber)
			if err != nil {
				log.Fatalf("Get current deposit key by btc height %d err %v", btcBlock.BlockNumber, err)
			}

			network := types.GetBTCNetwork(config.AppConfig.BTCNetworkType)

			// TODO verify SPV again

			// get vin
			pubkeyBytes, err := base64.StdEncoding.DecodeString(pubkey.PubKey)
			if err != nil {
				log.Fatalf("Base64 decode pubkey %s err %v", pubkey.PubKey, err)
			}
			p2pkhAddress, err := types.GenerateP2PKHAddress(pubkeyBytes, network)
			if err != nil {
				log.Fatalf("Gen P2PKH address from pubkey %s err %v", pubkey.PubKey, err)
			}
			p2wpkhAddress, err := types.GenerateP2WPKHAddress(pubkeyBytes, network)
			if err != nil {
				log.Fatalf("Gen P2WPKH address from pubkey %s err %v", pubkey.PubKey, err)
			}

			blockTxHashs := make([]string, 0)
			for _, tx := range btcBlock.Transactions {
				blockTxHashs = append(blockTxHashs, tx.TxID())
			}

			for _, tx := range btcBlock.Transactions {
				var utxos []*db.Utxo
				var vins []*db.Vin
				var vouts []*db.Vout
				// isUtxo means it will save to utxo table
				// isVin means it will save to vin|vout table

				isUtxo, isVin := false, false
				isWithdrawl, isDeposit, isConsolidation := false, false, false

				// query db send order to check isWithdrawl, isConsolidation
				sendOrder, err := w.state.GetSendOrderByTxIdOrExternalId(tx.TxID())
				if err != nil {
					log.Fatalf("Get send order by txid %s err %v", tx.TxID(), err)
				}
				if sendOrder != nil {
					if sendOrder.OrderType == db.ORDER_TYPE_WITHDRAWAL {
						isWithdrawl = true
					}
					if sendOrder.OrderType == db.ORDER_TYPE_CONSOLIDATION {
						isConsolidation = true
					}
				}

				sender, receiver := "", ""
				for _, vin := range tx.TxIn {
					_, addresses, requireSigs, err := txscript.ExtractPkScriptAddrs(vin.SignatureScript, network)
					if err != nil {
						log.Errorf("Error extracting input address, %v", err)
						continue
					}
					if len(addresses) == 0 {
						if (vin.PreviousOutPoint.Hash == chainhash.Hash{} && vin.PreviousOutPoint.Index == 0xffffffff) {
							sender = "coinbase"
							log.Debugf("Detect coinbase tx")
							break
						} else {
							log.Debugf("Extracting input address nil, txid: %s", tx.TxID())
							continue
						}
					}
					sender = addresses[0].EncodeAddress()

					if requireSigs > 1 {
						// ignore multi sigs
						continue
					}

					if sender == p2pkhAddress.EncodeAddress() || sender == p2wpkhAddress.EncodeAddress() {
						// should save vin db logic
						isVin = true
						// if TxOut len is 1 and receiver is self p2pkh|p2wpkh, it is consolidation
						// if TxOut len is 2+, or len is 1 but receiver is not self, it is withdrawal with change
						if len(tx.TxOut) == 1 {
							_, outZeroAddresses, outSigs, err := txscript.ExtractPkScriptAddrs(tx.TxOut[0].PkScript, network)
							if err == nil && outZeroAddresses != nil && outSigs == 1 {
								if outZeroAddresses[0].EncodeAddress() == p2pkhAddress.EncodeAddress() || outZeroAddresses[0].EncodeAddress() == p2wpkhAddress.EncodeAddress() {
									isConsolidation = true
								} else {
									isWithdrawl = true
								}
							}
						} else {
							isWithdrawl = true
						}
						vins = append(vins, &db.Vin{
							OrderId:   "",
							BtcHeight: btcBlock.BlockNumber,
							Txid:      vin.PreviousOutPoint.Hash.String(),
							OutIndex:  int(vin.PreviousOutPoint.Index),
							SigScript: vin.SignatureScript,
							Sender:    sender,
							Source:    db.UTXO_SOURCE_UNKNOWN,
							Status:    db.UTXO_STATUS_CONFIRMED,
							UpdatedAt: time.Now(),
						})
					}
				}

				var receiverType, evmAddr string
				magicBytes := w.state.GetL2Info().DepositMagic
				minDepositAmount := int64(w.state.GetL2Info().MinDepositAmount)
				isDeposit, evmAddr, _ = types.IsUtxoGoatDepositV1(tx, []btcutil.Address{p2pkhAddress, p2wpkhAddress}, network, minDepositAmount, magicBytes)

				for idx, vout := range tx.TxOut {
					_, addresses, requireSigs, err := txscript.ExtractPkScriptAddrs(vout.PkScript, network)
					if err != nil {
						log.Errorf("Error extracting output address, %v", err)
						continue
					}
					if len(addresses) == 0 {
						log.Debugf("Extracting output address nil, txid: %s", tx.TxID())
						continue
					}
					receiver = addresses[0].EncodeAddress()
					if requireSigs > 1 {
						// ignore multi sigs
						continue
					}

					if receiver == p2pkhAddress.EncodeAddress() {
						receiverType = db.WALLET_TYPE_P2PKH
					} else if receiver == p2wpkhAddress.EncodeAddress() {
						receiverType = db.WALLET_TYPE_P2WPKH
					} else {
						receiverType = db.WALLET_TYPE_UNKNOWN
					}
					// TODO check if it is p2wsh, and receiver exist in deposit result table with status processed
					if receiverType == db.WALLET_TYPE_P2PKH || receiverType == db.WALLET_TYPE_P2WPKH {
						// should save vout db logic
						isUtxo = true
						utxos = append(utxos, &db.Utxo{
							Uid:           "",
							Txid:          tx.TxID(),
							PkScript:      vout.PkScript,
							OutIndex:      idx,
							Amount:        vout.Value,
							Receiver:      receiver,
							WalletVersion: "1",
							Sender:        sender,
							EvmAddr:       evmAddr,
							Source:        db.UTXO_SOURCE_UNKNOWN,
							ReceiverType:  receiverType,
							Status:        db.UTXO_STATUS_CONFIRMED,
							ReceiveBlock:  btcBlock.BlockNumber,
							SpentBlock:    0,
							UpdatedAt:     time.Now(),
						})
					}
					vouts = append(vouts, &db.Vout{
						OrderId:    "",
						BtcHeight:  btcBlock.BlockNumber,
						Txid:       tx.TxID(),
						OutIndex:   idx,
						WithdrawId: "",
						Amount:     vout.Value,
						Receiver:   receiver,
						Sender:     sender,
						Source:     db.UTXO_SOURCE_UNKNOWN,
						Status:     db.UTXO_STATUS_CONFIRMED,
						UpdatedAt:  time.Now(),
					})
				}

				if isUtxo {
					// save utxo db, check if it is deposit from layer2
					for _, utxo := range utxos {
						if isDeposit {
							utxo.Source = db.UTXO_SOURCE_DEPOSIT
						} else if isConsolidation {
							utxo.Source = db.UTXO_SOURCE_CONSOLIDATION
						} else if isWithdrawl {
							utxo.Source = db.UTXO_SOURCE_WITHDRAWAL
						}
						noWitnessTx, _ := types.SerializeTransactionNoWitness(tx)
						merkleRoot, proofBytes, txIndex, err := types.GenerateSPVProof(utxo.Txid, blockTxHashs)
						if err != nil {
							log.Errorf("GenerateSPVProof err %v, txid: %s, block tx hashes: %s", err, utxo.Txid, blockTxHashs)
							continue
						}
						err = w.state.AddUtxo(utxo, pubkeyBytes, btcBlock.BlockHash().String(), btcBlock.BlockNumber, noWitnessTx, merkleRoot, proofBytes, txIndex, isDeposit)
						if err != nil {
							// TODO if err, update btc height before fatal quit
							log.Fatalf("Add utxo %v err %v", utxo, err)
						}
					}
				}
				if isVin {
					// save vin, vout db, check if it is withdraw from layer2
					for _, vin := range vins {
						if isDeposit {
							vin.Source = db.UTXO_SOURCE_DEPOSIT
						} else if isConsolidation {
							vin.Source = db.UTXO_SOURCE_CONSOLIDATION
						} else if isWithdrawl {
							vin.Source = db.UTXO_SOURCE_WITHDRAWAL
						}
						err = w.state.AddOrUpdateVin(vin)
						if err != nil {
							// TODO if err, update btc height before fatal quit
							log.Fatalf("Add vin %v err %v", vin, err)
						}
					}
					for _, vout := range vouts {
						if isDeposit {
							vout.Source = db.UTXO_SOURCE_DEPOSIT
						} else if isConsolidation {
							vout.Source = db.UTXO_SOURCE_CONSOLIDATION
						} else if isWithdrawl {
							vout.Source = db.UTXO_SOURCE_WITHDRAWAL
						}
						err = w.state.AddOrUpdateVout(vout)
						if err != nil {
							// TODO if err, update btc height before fatal quit
							log.Fatalf("Add vout %v err %v", vout, err)
						}
					}
				}

				// Note, if isUtxo && isVin, it is withdrawal||consolidation with change out to self
				if isWithdrawl || isConsolidation {
					log.Debugf("Update send order confirmed, txid: %s", tx.TxID())
					err = w.state.UpdateSendOrderConfirmed(tx.TxID(), btcBlock.BlockNumber)
					if err != nil {
						// this can be ignore, because recovery model order will not exitst
						log.Debugf("Update send order confirmed %v err %v", tx.TxID(), err)
					}
				}

				// Note, vout is P2WSH can not find here, it should query from BTC client in recovery model
			}
		}
	}
}
