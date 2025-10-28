package layer2

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/std"
	sdktypes "github.com/cosmos/cosmos-sdk/types"
	bitcointypes "github.com/goatnetwork/goat/x/bitcoin/types"
	relayertypes "github.com/goatnetwork/goat/x/relayer/types"

	"github.com/go-errors/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/goatnetwork/goat-relayer/internal/btc"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/layer2/abis"
	"github.com/goatnetwork/goat-relayer/internal/p2p"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"gorm.io/gorm"

	rpchttp "github.com/cometbft/cometbft/rpc/client/http"
	sdkclient "github.com/cosmos/cosmos-sdk/client"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	"bytes"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/goatnetwork/goat-relayer/internal/tss"
)

func makeEncodingConfig() EncodingConfig {
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	authtypes.RegisterInterfaces(interfaceRegistry)
	std.RegisterInterfaces(interfaceRegistry)
	relayertypes.RegisterInterfaces(interfaceRegistry)
	bitcointypes.RegisterInterfaces(interfaceRegistry)
	marshaler := codec.NewProtoCodec(interfaceRegistry)

	return EncodingConfig{
		InterfaceRegistry: interfaceRegistry,
		Codec:             marshaler,
		TxConfig:          authtx.NewTxConfig(marshaler, authtx.DefaultSignModes),
	}
}

type EncodingConfig struct {
	InterfaceRegistry codectypes.InterfaceRegistry
	Codec             codec.Codec
	TxConfig          sdkclient.TxConfig
}

// cosmos client
type Layer2Listener struct {
	libp2p    *p2p.LibP2PService
	db        *db.DatabaseManager
	state     *state.State
	ethClient *ethclient.Client

	hasVoterUpdate bool
	voterUpdateMu  sync.Mutex

	contractBitcoin        *abis.BitcoinContract
	contractBridge         *abis.BridgeContract
	contractRelayer        *abis.RelayerContract
	contractTaskManager    *abis.TaskManagerContract
	contractTaskManagerAbi *abi.ABI

	goatRpcClient   *rpchttp.HTTP
	goatGrpcConn    *grpc.ClientConn
	goatQueryClient authtypes.QueryClient
	goatSdkOnce     sync.Once
	txDecoder       sdktypes.TxDecoder

	sigFinishChan chan interface{}

	tssSigner *tss.Signer
	btcRPC    *btc.BTCRPCService
}

func NewLayer2Listener(libp2p *p2p.LibP2PService, state *state.State, db *db.DatabaseManager, btcClient *rpcclient.Client) *Layer2Listener {
	ethClient, err := DialEthClient()
	if err != nil {
		log.Fatalf("Error creating Layer2 EVM RPC client: %v", err)
	}
	contractTaskManagerAbi, err := abi.JSON(strings.NewReader(abis.TaskManagerContractABI))
	if err != nil {
		log.Fatalf("Failed to parse task manager abi: %v", err)
		return nil
	}
	contractRelayer, err := abis.NewRelayerContract(abis.RelayerAddress, ethClient)
	if err != nil {
		log.Fatalf("Failed to instantiate contract relayer: %v", err)
	}
	contractBitcoin, err := abis.NewBitcoinContract(abis.BitcoinAddress, ethClient)
	if err != nil {
		log.Fatalf("Failed to instantiate contract bitcoin: %v", err)
	}
	contractBridge, err := abis.NewBridgeContract(abis.BridgeAddress, ethClient)
	if err != nil {
		log.Fatalf("Failed to instantiate contract bridge: %v", err)
	}
	contractTaskManager, err := abis.NewTaskManagerContract(common.HexToAddress(config.AppConfig.ContractTaskManager), ethClient)
	if err != nil {
		log.Fatalf("Failed to instantiate contract task manager: %v", err)
	}

	goatRpcClient, goatGrpcConn, goatQueryCLient, err := DialCosmosClient()
	if err != nil {
		log.Fatalf("Error creating Layer2 Cosmos RPC client: %v", err)
	}

	encodingConfig := makeEncodingConfig()
	txDecoder := encodingConfig.TxConfig.TxDecoder()

	// Initialize TSS signer
	tssSigner := tss.NewSigner(config.AppConfig.TssEndpoint, big.NewInt(config.AppConfig.L2ChainId.Int64()))

	// Initialize BTC RPC service
	btcRPC := btc.NewBTCRPCService(btcClient)

	return &Layer2Listener{
		libp2p:    libp2p,
		db:        db,
		state:     state,
		ethClient: ethClient,

		contractBitcoin:        contractBitcoin,
		contractBridge:         contractBridge,
		contractRelayer:        contractRelayer,
		contractTaskManager:    contractTaskManager,
		contractTaskManagerAbi: &contractTaskManagerAbi,

		goatRpcClient:   goatRpcClient,
		goatGrpcConn:    goatGrpcConn,
		goatQueryClient: goatQueryCLient,
		txDecoder:       txDecoder,

		sigFinishChan: make(chan interface{}, 256),
		tssSigner:     tssSigner,
		btcRPC:        btcRPC,
	}
}

// New an eth client
func DialEthClient() (*ethclient.Client, error) {
	var opts []rpc.ClientOption

	if config.AppConfig.L2JwtSecret != "" {
		jwtSecret := common.FromHex(strings.TrimSpace(config.AppConfig.L2JwtSecret))
		if len(jwtSecret) != 32 {
			return nil, errors.New("jwt secret is not a 32 bytes hex string")
		}
		var jwtKey [32]byte
		copy(jwtKey[:], jwtSecret)
		opts = append(opts, rpc.WithHTTPAuth(node.NewJWTAuth(jwtKey)))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	// Dial the Ethereum node with optional JWT authentication
	client, err := rpc.DialOptions(ctx, config.AppConfig.L2RPC, opts...)
	if err != nil {
		return nil, err
	}
	return ethclient.NewClient(client), nil
}

// New a cosmos client, contains rpcClient & queryClient
func DialCosmosClient() (*rpchttp.HTTP, *grpc.ClientConn, authtypes.QueryClient, error) {
	// An http client without websocket, if use websocket, should start and stop
	rpcClient, err := rpchttp.New(config.AppConfig.GoatChainRPCURI, "/")
	if err != nil {
		return nil, nil, nil, err
	}
	grpcConn, err := grpc.NewClient(config.AppConfig.GoatChainGRPCURI, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, nil, err
	}
	queryClient := authtypes.NewQueryClient(grpcConn)
	return rpcClient, grpcConn, queryClient, nil
}

func (lis *Layer2Listener) checkAndReconnect() error {
	// Check the gRPC connection state
	if lis.goatGrpcConn.GetState() == connectivity.Shutdown || lis.goatGrpcConn.GetState() == connectivity.TransientFailure {
		log.Debug("gRPC connection is not usable, reconnecting...")

		// Close the old connection
		if lis.goatGrpcConn.GetState() != connectivity.Shutdown {
			err := lis.goatGrpcConn.Close()
			if err != nil {
				return err
			}
		}

		// Recreate the gRPC connection and QueryClient
		newRpcClient, newGrpcConn, newQueryClient, err := DialCosmosClient()
		if err != nil {
			return err
		}

		// Update the manager with new connections
		lis.goatRpcClient = newRpcClient
		lis.goatGrpcConn = newGrpcConn
		lis.goatQueryClient = newQueryClient

		log.Debug("gRPC reconnecting ok...")
	}

	return nil
}

func (lis *Layer2Listener) Start(ctx context.Context) {
	go lis.listenConsensusEvents(ctx)
}

func (lis *Layer2Listener) listenConsensusEvents(ctx context.Context) {
	// Get latest sync height
	var syncStatus db.L2SyncStatus
	l2SyncDB := lis.db.GetL2SyncDB()
	result := l2SyncDB.First(&syncStatus)
	if result.Error == gorm.ErrRecordNotFound {
		syncStatus.LastSyncBlock = uint64(config.AppConfig.L2StartHeight)
		syncStatus.UpdatedAt = time.Now()
		l2SyncDB.Create(&syncStatus)
	} else if result.Error != nil {
		log.Fatalf("Error querying sync status: %v", result.Error)
	}

	l2RequestInterval := config.AppConfig.L2RequestInterval
	l2AbortInterval, _ := time.ParseDuration(fmt.Sprintf("%fs", l2RequestInterval.Seconds()+2))
	l2Confirmations := uint64(config.AppConfig.L2Confirmations)
	l2MaxBlockRange := uint64(config.AppConfig.L2MaxBlockRange)
	// clientTimeout := time.Second * 10
	var l2LatestBlock uint64

	for {
		select {
		case <-ctx.Done():
			log.Info("Layer2Listener stopping...")
			lis.stop()
			return
		default:
			// ctx1, cancel1 := context.WithTimeout(ctx, clientTimeout)
			// latestBlock, err := lis.ethClient.BlockNumber(ctx1)
			// cancel1()
			// if err != nil {
			// 	log.Errorf("Error getting latest block number: %v", err)
			// 	time.Sleep(l2RequestInterval)
			// 	continue
			// }

			status, err := lis.goatRpcClient.Status(ctx)
			if err != nil {
				log.Errorf("Error getting goat chain status: %v", err)
				time.Sleep(l2AbortInterval)
				continue
			}

			latestBlock := uint64(status.SyncInfo.LatestBlockHeight)
			targetBlock := latestBlock - l2Confirmations
			fromBlock := syncStatus.LastSyncBlock + 1

			if fromBlock == 1 {
				l2Info, voters, epoch, sequence, proposer, err := lis.getGoatChainGenesisState(ctx)
				if err != nil {
					log.Fatalf("Failed to get genesis state: %v", err)
				}
				pubKeyResp, err := lis.QueryPubKey(ctx)
				if err != nil {
					log.Fatalf("Failed to query pub key: %v", err)
				}
				err = lis.processFirstBlock(l2Info, voters, epoch, sequence, proposer, pubKeyResp.PublicKey)
				if err != nil {
					log.Fatalf("Failed to process genesis state: %v", err)
				}
			}

			layer2Info := lis.state.GetL2Info()
			paramsResp, err := lis.QueryParams(ctx)
			if err != nil || paramsResp.Params.MinDepositAmount == 0 || len(paramsResp.Params.DepositMagicPrefix) == 0 {
				log.Fatalf("Failed to query params: %v", err)
			}
			if layer2Info.MinDepositAmount != paramsResp.Params.MinDepositAmount || !bytes.Equal(layer2Info.DepositMagic, paramsResp.Params.DepositMagicPrefix) {
				err = lis.processParams(paramsResp.Params)
				if err != nil {
					log.Fatalf("Failed to process params: %v", err)
				}
			}

			if status.SyncInfo.CatchingUp {
				log.Infof("Goat chain is catching up, current height %d", latestBlock)
			} else {
				log.Debugf("Goat chain is up to date, current height %d", latestBlock)
			}

			if latestBlock > l2LatestBlock {
				l2LatestBlock = latestBlock
				// Update l2 info
				err = lis.processChainStatus(latestBlock, l2Confirmations, status.SyncInfo.CatchingUp)
				if err != nil {
					log.Errorf("Error processChainStatus: %v", err)
					time.Sleep(l2AbortInterval)
					continue
				}
			}

			if syncStatus.LastSyncBlock < targetBlock {
				toBlock := min(fromBlock+l2MaxBlockRange-1, targetBlock)

				log.WithFields(log.Fields{
					"fromBlock": fromBlock,
					"toBlock":   toBlock,
				}).Info("Syncing L2 goat events")

				lis.voterUpdateMu.Lock()
				if !lis.hasVoterUpdate && fromBlock > 1 {
					err := lis.processBlockVoters(fromBlock)
					if err != nil {
						log.Errorf("Error processBlockVoters at block %d: %v", fromBlock, err)
						lis.voterUpdateMu.Unlock()
						time.Sleep(l2RequestInterval)
						continue
					} else {
						lis.hasVoterUpdate = true
						log.Infof("Goat chain voters synced at block %d", fromBlock)
					}
				}
				lis.voterUpdateMu.Unlock()

				// Query cosmos tx or event
				goatRpcAbort := false
				for height := fromBlock; height <= toBlock; height++ {
					err = lis.getGoatBlock(ctx, height)
					if err != nil {
						log.Errorf("Failed to process block %d: %v", height, err)
						goatRpcAbort = true
						break
					}
					// update LastSyncBlock
					syncStatus.LastSyncBlock = height
				}

				// Save sync status
				syncStatus.UpdatedAt = time.Now()
				l2SyncDB.Save(&syncStatus)

				if goatRpcAbort {
					time.Sleep(l2AbortInterval)
					continue
				}
			} else {
				log.Debugf("Sync to tip, target block: %d", targetBlock)
			}

			time.Sleep(l2RequestInterval)
		}
	}
}

// stop ctx
func (lis *Layer2Listener) stop() {
	if lis.goatGrpcConn != nil && lis.goatGrpcConn.GetState() != connectivity.Shutdown {
		lis.goatGrpcConn.Close()
	}
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func (lis *Layer2Listener) filterEvmEvents(ctx context.Context, hash string) error {
	blockHash := common.HexToHash(hash)
	contractAddr := common.HexToAddress(config.AppConfig.ContractTaskManager)

	log.Infof("Filtering EVM events for block hash: %s, contract address: %s", hash, contractAddr.Hex())

	logs, err := lis.ethClient.FilterLogs(ctx, ethereum.FilterQuery{
		BlockHash: &blockHash,
		Addresses: []common.Address{
			contractAddr,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to filter evm events: %w", err)
	}

	log.Infof("Filtered %d evm events", len(logs))
	for _, vlog := range logs {
		log.Infof("Processing event with topics: %v", vlog.Topics)
		switch vlog.Topics[0] {
		case lis.contractTaskManagerAbi.Events["TaskCreated"].ID:
			log.Infof("Found TaskCreated event")
			taskCreatedEvent := abis.TaskManagerContractTaskCreated{}
			err := lis.contractTaskManagerAbi.UnpackIntoInterface(&taskCreatedEvent, "TaskCreated", vlog.Data)
			if err != nil {
				log.Errorf("failed to unpack task created event: %v", err)
				return err
			}
			log.Infof("Successfully unpacked TaskCreated event with taskId: %v", taskCreatedEvent.TaskId)
			err = lis.handleTaskCreated(ctx, taskCreatedEvent.TaskId)
			if err != nil {
				log.Errorf("failed to handle task created event: %v", err)
				return err
			}
			log.Infof("Successfully handled TaskCreated event")
		case lis.contractTaskManagerAbi.Events["FundsReceived"].ID:
			fundsReceivedEvent := abis.TaskManagerContractFundsReceived{}
			err := lis.contractTaskManagerAbi.UnpackIntoInterface(&fundsReceivedEvent, "FundsReceived", vlog.Data)
			if err != nil {
				log.Errorf("failed to unpack funds received event: %v", err)
				return err
			}
			err = lis.handleFundsReceived(fundsReceivedEvent.TaskId, fundsReceivedEvent.FundingTxHash[:], uint64(fundsReceivedEvent.TxOut), uint64(fundsReceivedEvent.TimelockEndTime))
			if err != nil {
				log.Errorf("failed to handle funds received event: %v", err)
				return err
			}
		case lis.contractTaskManagerAbi.Events["TaskCancelled"].ID:
			taskCancelledEvent := abis.TaskManagerContractTaskCancelled{}
			err := lis.contractTaskManagerAbi.UnpackIntoInterface(&taskCancelledEvent, "TaskCancelled", vlog.Data)
			if err != nil {
				log.Errorf("failed to unpack task cancelled event: %v", err)
				return err
			}
			err = lis.handleTaskCancelled(taskCancelledEvent.TaskId)
			if err != nil {
				log.Errorf("failed to handle task cancelled event: %v", err)
				return err
			}
			log.Infof("Successfully handled TaskCancelled event")
		case lis.contractTaskManagerAbi.Events["TimelockInitialized"].ID:
			timelockInitializedEvent := abis.TaskManagerContractTimelockInitialized{}
			err := lis.contractTaskManagerAbi.UnpackIntoInterface(&timelockInitializedEvent, "TimelockInitialized", vlog.Data)
			if err != nil {
				log.Errorf("failed to unpack timelock initialized event: %v", err)
				return err
			}
			err = lis.handleTimelockInitialized(ctx, timelockInitializedEvent.TaskId, timelockInitializedEvent.TimelockTxHash[:], uint64(timelockInitializedEvent.TxOut))
			if err != nil {
				log.Errorf("failed to handle timelock initialized event: %v", err)
				return err
			}
			log.Infof("Successfully handled TimelockInitialized event")
		case lis.contractTaskManagerAbi.Events["TimelockProcessed"].ID:
			timelockProcessedEvent := abis.TaskManagerContractTimelockProcessed{}
			err := lis.contractTaskManagerAbi.UnpackIntoInterface(&timelockProcessedEvent, "TimelockProcessed", vlog.Data)
			if err != nil {
				log.Errorf("failed to unpack timelock processed event: %v", err)
				return err
			}
			err = lis.handleTimelockProcessed(ctx, timelockProcessedEvent.TaskId)
			if err != nil {
				log.Errorf("failed to handle timelock confirmed ok event: %v", err)
				return err
			}
			log.Infof("Successfully handled TimelockConfirmedOK event")
		case lis.contractTaskManagerAbi.Events["Burned"].ID:
			burnedEvent := abis.TaskManagerContractBurned{}
			err := lis.contractTaskManagerAbi.UnpackIntoInterface(&burnedEvent, "Burned", vlog.Data)
			if err != nil {
				log.Errorf("failed to unpack burned event: %v", err)
				return err
			}
			err = lis.handleBurned(ctx, burnedEvent.TaskId)
			if err != nil {
				log.Errorf("failed to handle burned event: %v", err)
				return err
			}
			log.Infof("Successfully handled Burned event")
		default:
			log.Infof("Unknown event: %v", vlog.Topics)
		}

	}

	return nil
}

func (lis *Layer2Listener) getGoatBlock(ctx context.Context, height uint64) error {
	block := int64(height)
	blockResults, err := lis.goatRpcClient.BlockResults(ctx, &block)
	if err != nil {
		return fmt.Errorf("failed to get block results: %w", err)
	}

	blockData, err := lis.goatRpcClient.Block(ctx, &block)
	if err != nil {
		return fmt.Errorf("failed to get block data: %w", err)
	}

	// Process events and handle logic
	for i, txResult := range blockResults.TxsResults {
		if txResult.Code == 0 && len(txResult.Data) > 0 {
			// only process success tx
			decodedTx, err := lis.txDecoder(blockData.Block.Data.Txs[i])
			if err == nil {
				log.Debugf("Success to decode transaction: %v", decodedTx.GetMsgs())
				for _, msg := range decodedTx.GetMsgs() {
					switch msg := msg.(type) {
					case *bitcointypes.MsgProcessWithdrawalV2:
						if err := lis.processMsgInitializeWithdrawal(msg); err != nil {
							return fmt.Errorf("failed to process msg InitializeWithdrawal: %v", err)
						}
					}
				}
			}
		}

		for _, event := range txResult.Events {
			if err := lis.processEvent(ctx, height, event); err != nil {
				return fmt.Errorf("failed to process tx event %s: %w", event.Type, err)
			}
		}
	}

	for _, event := range blockResults.FinalizeBlockEvents {
		if err := lis.processEvent(ctx, height, event); err != nil {
			return fmt.Errorf("failed to process EndBlock event %s: %w", event.Type, err)
		}
	}

	// End block processing
	if err := lis.processEndBlock(height); err != nil {
		return fmt.Errorf("failed to process end block: %w", err)
	}
	return nil
}

func (lis *Layer2Listener) getGoatChainGenesisState(ctx context.Context) (*db.L2Info, []*db.Voter, uint64, uint64, string, error) {
	defer lis.stop()

	interfaceRegistry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(interfaceRegistry)

	genesis, err := lis.goatRpcClient.Genesis(ctx)
	if err != nil {
		log.Errorf("Error getting goat chain genesis: %v", err)
		return nil, nil, 0, 0, "", err
	}

	var appState map[string]json.RawMessage
	if err := json.Unmarshal(genesis.Genesis.AppState, &appState); err != nil {
		log.Errorf("Error unmarshalling genesis doc: %v", err)
		return nil, nil, 0, 0, "", err
	}

	var bitcoinState bitcointypes.GenesisState
	if err := cdc.UnmarshalJSON(appState[bitcointypes.ModuleName], &bitcoinState); err != nil {
		log.Errorf("Error unmarshalling bitcoin state: %v", err)
		return nil, nil, 0, 0, "", err
	}

	var relayerState relayertypes.GenesisState
	if err := cdc.UnmarshalJSON(appState[relayertypes.ModuleName], &relayerState); err != nil {
		log.Errorf("Error unmarshalling relayer state: %v", err)
		return nil, nil, 0, 0, "", err
	}

	l2Info := &db.L2Info{
		Height:          1,
		Syncing:         true,
		Threshold:       "2/3",
		DepositKey:      ",",
		StartBtcHeight:  bitcoinState.BlockTip,
		LatestBtcHeight: bitcoinState.BlockTip,
		UpdatedAt:       time.Now(),
	}

	voters := []*db.Voter{}
	for _, voterAddress := range relayerState.Relayer.Voters {
		voters = append(voters, &db.Voter{
			VoteAddr:  voterAddress,
			VoteKey:   "",
			Height:    1,
			UpdatedAt: time.Now(),
		})
	}

	return l2Info, voters, relayerState.Relayer.Epoch, relayerState.Sequence, relayerState.Relayer.Proposer, nil
}

func (lis *Layer2Listener) GetContractTaskManager() *abis.TaskManagerContract {
	return lis.contractTaskManager
}

func (lis *Layer2Listener) GetGoatEthClient() *ethclient.Client {
	return lis.ethClient
}
