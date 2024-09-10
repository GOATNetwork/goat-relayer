package layer2

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	bitcointypes "github.com/goatnetwork/goat/x/bitcoin/types"
	relayertypes "github.com/goatnetwork/goat/x/relayer/types"
	"strings"
	"time"

	"github.com/go-errors/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/layer2/abis"
	"github.com/goatnetwork/goat-relayer/internal/p2p"
	"github.com/goatnetwork/goat-relayer/internal/state"
	"gorm.io/gorm"

	rpchttp "github.com/cometbft/cometbft/rpc/client/http"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
)

// cosmos client
type Layer2Listener struct {
	libp2p    *p2p.LibP2PService
	db        *db.DatabaseManager
	state     *state.State
	ethClient *ethclient.Client

	contractBitcoin *abis.BitcoinContract
	contractBridge  *abis.BridgeContract
	contractRelayer *abis.RelayerContract

	goatRpcClient   *rpchttp.HTTP
	goatGrpcConn    *grpc.ClientConn
	goatQueryClient authtypes.QueryClient
}

func NewLayer2Listener(libp2p *p2p.LibP2PService, state *state.State, db *db.DatabaseManager) *Layer2Listener {
	ethClient, err := DialEthClient()
	if err != nil {
		log.Fatalf("Error creating Layer2 EVM RPC client: %v", err)
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

	goatRpcClient, goatGrpcConn, goatQueryCLient, err := DialCosmosClient()
	if err != nil {
		log.Fatalf("Error creating Layer2 Cosmos RPC client: %v", err)
	}

	return &Layer2Listener{
		libp2p:    libp2p,
		db:        db,
		state:     state,
		ethClient: ethClient,

		contractBitcoin: contractBitcoin,
		contractBridge:  contractBridge,
		contractRelayer: contractRelayer,

		goatRpcClient:   goatRpcClient,
		goatGrpcConn:    goatGrpcConn,
		goatQueryClient: goatQueryCLient,
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

func (lis *Layer2Listener) Start(ctx context.Context) {
	// Get latest sync height
	var syncStatus db.L2SyncStatus
	l2SyncDB := lis.db.GetL2SyncDB()
	result := l2SyncDB.First(&syncStatus)
	if result.Error != nil && result.Error == gorm.ErrRecordNotFound {
		syncStatus.LastSyncBlock = uint64(config.AppConfig.L2StartHeight)
		syncStatus.UpdatedAt = time.Now()
		l2SyncDB.Create(&syncStatus)
	}

	l2RequestInterval := config.AppConfig.L2RequestInterval
	l2Confirmations := uint64(config.AppConfig.L2Confirmations)
	l2MaxBlockRange := uint64(config.AppConfig.L2MaxBlockRange)
	clientTimeout := time.Second * 10

	for {
		select {
		case <-ctx.Done():
			log.Info("Layer2Listener stoping...")
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

			ctx1, cancel1 := context.WithTimeout(ctx, clientTimeout)
			status, err := lis.goatRpcClient.Status(ctx1)
			cancel1()
			if err != nil {
				log.Errorf("Error getting goat chain status: %v", err)
				time.Sleep(l2RequestInterval)
				continue
			}

			latestBlock := uint64(status.SyncInfo.LatestBlockHeight)

			// Update l2 info
			lis.processChainStatus(latestBlock, status.SyncInfo.CatchingUp)
			if status.SyncInfo.CatchingUp {
				log.Debugf("Goat chain is catching up, current height %d", latestBlock)
			} else {
				log.Debugf("Goat chain is up to date, current height %d", latestBlock)
			}

			targetBlock := latestBlock - l2Confirmations
			if syncStatus.LastSyncBlock < targetBlock {
				fromBlock := syncStatus.LastSyncBlock + 1
				toBlock := min(fromBlock+l2MaxBlockRange-1, targetBlock)

				log.WithFields(log.Fields{
					"fromBlock": fromBlock,
					"toBlock":   toBlock,
				}).Info("Syncing L2 goat events")

				//// Filter evm event
				// filterQuery := ethereum.FilterQuery{
				// 	FromBlock: big.NewInt(int64(fromBlock)),
				// 	ToBlock:   big.NewInt(int64(toBlock)),
				// 	Addresses: []common.Address{abis.BridgeAddress, abis.BitcoinAddress, abis.RelayerAddress},
				// }

				// ctx2, cancel2 := context.WithTimeout(ctx, clientTimeout)
				// logs, err := lis.ethClient.FilterLogs(ctx2, filterQuery)
				// cancel2()
				// if err != nil {
				// 	log.Errorf("Failed to filter logs: %v", err)
				// 	time.Sleep(l2RequestInterval)
				// 	continue
				// }

				// for _, vLog := range logs {
				// 	lis.processGoatLogs(vLog)
				// 	// if syncStatus.LastSyncBlock < vLog.BlockNumber {
				// 	// 	syncStatus.LastSyncBlock = vLog.BlockNumber
				// 	// }
				// }

				if fromBlock == 1 {
					l2Info, voters, err := lis.getGoatChainGenesisState(ctx)
					if err != nil {
						log.Errorf("Failed to get genesis state: %v", err)
					} else {
						lis.processFirstBlock(l2Info, voters)
					}
				}

				// Query cosmos tx or event
				goatRpcAbort := false
				for height := fromBlock; height <= toBlock; height++ {
					block := int64(height)
					ctx3, cancel3 := context.WithTimeout(ctx, clientTimeout)
					blockResults, err := lis.goatRpcClient.BlockResults(ctx3, &block)
					cancel3()
					if err != nil {
						log.Errorf("Failed to get cosmos block results at height %d: %v", height, err)
						goatRpcAbort = true
						break
					}

					syncStatus.LastSyncBlock = height

					for _, txResult := range blockResults.TxsResults {
						for _, event := range txResult.Events {
							lis.processEvent(height, event)
						}
					}
					lis.processEndBlock(height)
				}

				// Save sync status
				syncStatus.UpdatedAt = time.Now()
				l2SyncDB.Save(&syncStatus)

				if goatRpcAbort {
					time.Sleep(l2RequestInterval)
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
	if lis.goatGrpcConn != nil {
		lis.goatGrpcConn.Close()
	}
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func (lis *Layer2Listener) getGoatChainGenesisState(ctx context.Context) (*db.L2Info, []*db.Voter, error) {
	defer lis.stop()

	interfaceRegistry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(interfaceRegistry)

	genesis, err := lis.goatRpcClient.Genesis(ctx)
	if err != nil {
		log.Errorf("Error getting goat chain genesis: %v", err)
		return nil, nil, err
	}

	var appState map[string]json.RawMessage
	if err := json.Unmarshal(genesis.Genesis.AppState, &appState); err != nil {
		log.Errorf("Error unmarshalling genesis doc: %s", err)
		return nil, nil, err
	}

	var bitcoinState bitcointypes.GenesisState
	if err := cdc.UnmarshalJSON(appState[bitcointypes.ModuleName], &bitcoinState); err != nil {
		log.Errorf("Error unmarshalling bitcoin state: %s", err)
		return nil, nil, err
	}

	var relayerState relayertypes.GenesisState
	if err := cdc.UnmarshalJSON(appState[relayertypes.ModuleName], &relayerState); err != nil {
		log.Errorf("Error unmarshalling relayer state: %s", err)
		return nil, nil, err
	}

	l2Info := &db.L2Info{
		Height:          1,
		Syncing:         true,
		Threshold:       "2/3",
		DepositKey:      hex.EncodeToString(bitcoinState.Pubkey.GetSecp256K1()),
		StartBtcHeight:  bitcoinState.StartBlockNumber,
		LatestBtcHeight: 0,
		UpdatedAt:       time.Now(),
	}

	voters := []*db.Voter{}
	for address, voter := range relayerState.Voters {
		voters = append(voters, &db.Voter{
			VoteAddr:  address,
			VoteKey:   hex.EncodeToString(voter.VoteKey),
			Height:    1,
			UpdatedAt: time.Now(),
		})
	}

	return l2Info, voters, nil
}
