package rpc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/goatnetwork/goat-relayer/internal/layer2"
	"github.com/goatnetwork/goat-relayer/internal/state"
	bitcointypes "github.com/goatnetwork/goat/x/bitcoin/types"
	"google.golang.org/grpc/credentials/insecure"
	"net"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/btc"
	"github.com/goatnetwork/goat-relayer/internal/config"
	pb "github.com/goatnetwork/goat-relayer/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	log "github.com/sirupsen/logrus"
)

type UtxoServer struct {
	pb.UnimplementedBitcoinLightWalletServer
	state          *state.State
	layer2Listener *layer2.Layer2Listener
}

func (s *UtxoServer) Start(ctx context.Context) {
	addr := ":" + config.AppConfig.RPCPort
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	server := grpc.NewServer()
	pb.RegisterBitcoinLightWalletServer(server, &UtxoServer{})
	reflection.Register(server)

	log.Infof("gRPC server is running on port %s", config.AppConfig.RPCPort)
	if err := server.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func NewUtxoServer(state *state.State, layer2Listener *layer2.Layer2Listener) *UtxoServer {
	return &UtxoServer{
		state:          state,
		layer2Listener: layer2Listener,
	}
}

func (s *UtxoServer) NewTransaction(ctx context.Context, req *pb.NewTransactionRequest) (*pb.NewTransactionResponse, error) {
	var tx wire.MsgTx
	if err := json.NewDecoder(bytes.NewReader(req.RawTransaction)).Decode(&tx); err != nil {
		log.Errorf("Failed to decode transaction: %v", err)
		return nil, err
	}

	if err := btc.VerifyTransaction(req.RawTransaction); err != nil {
		return nil, err
	}

	s.state.AddUnconfirmDeposit(req.TransactionId, hex.EncodeToString(req.RawTransaction), req.EvmAddress)

	return &pb.NewTransactionResponse{
		ErrorMessage: "Confirming transaction",
	}, nil
}

func (s *UtxoServer) QueryDepositAddress(ctx context.Context, req *pb.QueryDepositAddressRequest) (*pb.QueryDepositAddressResponse, error) {
	//l2Info := s.state.GetL2Info()
	//
	//publicKey, err := hex.DecodeString(l2Info.DepositKey)
	//if err != nil {
	//	return nil, err
	//}

	//pubkeyResponse := s.layer2Listener.QueryPubKey(ctx)

	grpcConn, err := grpc.NewClient(config.AppConfig.GoatChainGRPCURI, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	client := bitcointypes.NewQueryClient(grpcConn)
	pubkeyResponse, err := client.Pubkey(ctx, &bitcointypes.QueryPubkeyRequest{})
	if err != nil {
		log.Errorf("Error while querying relayer status: %v", err)
	}

	pubKey := pubkeyResponse.PublicKey.GetSecp256K1()

	network := &chaincfg.MainNetParams
	p2wpkh, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pubKey), network)
	if err != nil {
		return nil, err
	}

	return &pb.QueryDepositAddressResponse{
		DepositAddress: p2wpkh.EncodeAddress(),
	}, nil
}
