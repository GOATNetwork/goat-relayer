package wallet

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
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
				continue
			}

			var network *chaincfg.Params
			switch config.AppConfig.BTCNetworkType {
			case "":
				network = &chaincfg.MainNetParams
			case "mainnet":
				network = &chaincfg.MainNetParams
			case "regtest":
				network = &chaincfg.RegressionNetParams
			case "testnet3":
				network = &chaincfg.TestNet3Params
			}

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

			for _, tx := range btcBlock.Transactions {
				var utxos []*db.Utxo
				var vins []*db.Vin
				var vouts []*db.Vout
				// isUtxo means it will save to utxo table
				// isVin means it will save to vin|vout table

				isUtxo, isVin := false, false
				isWithdrawl, isDeposit, isConsolidation := false, false, false
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
							log.Errorf("Error extracting input address nil")
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
							Sender:    addresses[0].EncodeAddress(),
							Source:    "unknown",
							Status:    "confirmed",
							UpdatedAt: time.Now(),
						})
					}
				}

				var receiverType, evmAddr string
				isDeposit, evmAddr = types.IsUtxoGoatDepositV1(tx, []btcutil.Address{p2pkhAddress, p2wpkhAddress}, network)

				for idx, vout := range tx.TxOut {
					_, addresses, requireSigs, err := txscript.ExtractPkScriptAddrs(vout.PkScript, network)
					if err != nil {
						log.Errorf("Error extracting output address, %v", err)
						continue
					}
					if len(addresses) == 0 {
						log.Debugf("Extracting output address nil")
						continue
					}
					receiver = addresses[0].EncodeAddress()
					if requireSigs > 1 {
						// ignore multi sigs
						continue
					}

					if receiver == p2pkhAddress.EncodeAddress() {
						receiverType = "P2PKH"
					} else if receiver == p2wpkhAddress.EncodeAddress() {
						receiverType = "P2WPKH"
					}
					if receiverType == "P2PKH" || receiverType == "P2WPKH" {
						// should save vout db logic
						isUtxo = true
						utxos = append(utxos, &db.Utxo{
							Uid:           "",
							Txid:          tx.TxHash().String(),
							PkScript:      vout.PkScript,
							OutIndex:      idx,
							Amount:        vout.Value,
							Receiver:      receiver,
							WalletVersion: "1",
							Sender:        sender,
							EvmAddr:       evmAddr,
							Source:        "unknown",
							ReceiverType:  receiverType,
							Status:        "confirmed",
							ReceiveBlock:  btcBlock.BlockNumber,
							SpentBlock:    0,
							UpdatedAt:     time.Now(),
						})
					}
					vouts = append(vouts, &db.Vout{
						OrderId:    "",
						BtcHeight:  btcBlock.BlockNumber,
						Txid:       tx.TxHash().String(),
						OutIndex:   idx,
						WithdrawId: "",
						Amount:     vout.Value,
						Receiver:   receiver,
						Sender:     sender,
						Source:     "unknown",
						Status:     "confirmed",
						UpdatedAt:  time.Now(),
					})
				}

				if isUtxo {
					// save utxo db, check if it is deposit from layer2
					for _, utxo := range utxos {
						if isDeposit {
							utxo.Source = "deposit"
						} else if isConsolidation {
							utxo.Source = "consolidation"
						} else if isWithdrawl {
							utxo.Source = "withdrawal"
						}
						err = w.state.AddUtxo(utxo)
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
							vin.Source = "deposit"
						} else if isConsolidation {
							vin.Source = "consolidation"
						} else if isWithdrawl {
							vin.Source = "withdrawal"
						}
						err = w.state.AddOrUpdateVin(vin)
						if err != nil {
							// TODO if err, update btc height before fatal quit
							log.Fatalf("Add vin %v err %v", vin, err)
						}
					}
					for _, vout := range vouts {
						if isDeposit {
							vout.Source = "deposit"
						} else if isConsolidation {
							vout.Source = "consolidation"
						} else if isWithdrawl {
							vout.Source = "withdrawal"
						}
						err = w.state.AddOrUpdateVout(vout)
						if err != nil {
							// TODO if err, update btc height before fatal quit
							log.Fatalf("Add vout %v err %v", vout, err)
						}
					}
				}

				// Note, if isUtxo && isVin, it is withdrawal|consolidation with change out to self

				// Note, vout is P2WSH can not find here, it should query from BTC client in recovery model
			}
		}
	}
}
