package rpc

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/types"

	"net"

	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/layer2"
	"github.com/goatnetwork/goat-relayer/internal/p2p"
	"github.com/goatnetwork/goat-relayer/internal/state"
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
		log.Fatalf("Failed to listen: %v", err)
	}

	server := grpc.NewServer()
	pb.RegisterBitcoinLightWalletServer(server, s)
	reflection.Register(server)

	log.Infof("GRPC server is running on port %s", config.AppConfig.RPCPort)
	if err := server.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

func NewUtxoServer(state *state.State, layer2Listener *layer2.Layer2Listener) *UtxoServer {
	return &UtxoServer{
		state:          state,
		layer2Listener: layer2Listener,
	}
}

func (s *UtxoServer) NewTransaction(ctx context.Context, req *pb.NewTransactionRequest) (*pb.NewTransactionResponse, error) {
	rawTxBytes, err := hex.DecodeString(req.RawTransaction)
	if err != nil {
		return nil, err
	}

	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(rawTxBytes)); err != nil {
		log.Errorf("Failed to decode transaction: %v", err)
		return nil, err
	}

	evmAddr := strings.TrimPrefix(req.EvmAddress, "0x")

	isTrue, signVersion, outputIndex, amount, err := s.VerifyDeposit(tx, evmAddr)
	if err != nil || !isTrue || outputIndex == -1 {
		log.Errorf("Failed to verify deposit: %v", err)
		return nil, err
	}

	err = s.state.AddUnconfirmDeposit(req.TransactionId, req.RawTransaction, evmAddr, signVersion, outputIndex, amount)
	if err != nil {
		log.Errorf("Failed to add unconfirmed deposit: %v", err)
		return nil, err
	}

	deposit := types.MsgUtxoDeposit{
		RawTx:       req.RawTransaction,
		TxId:        req.TransactionId,
		EvmAddr:     evmAddr,
		SignVersion: signVersion,
		OutputIndex: outputIndex,
		Amount:      amount,
		Timestamp:   time.Now().Unix(),
	}

	err = p2p.PublishMessage(context.Background(), p2p.Message{
		MessageType: p2p.MessageTypeDepositReceive,
		RequestId:   fmt.Sprintf("DEPOSIT:%s:%s", config.AppConfig.RelayerAddress, deposit.TxId),
		DataType:    "MsgUtxoDeposit",
		Data:        deposit,
	})
	if err != nil {
		return nil, err
	}

	return &pb.NewTransactionResponse{
		ErrorMessage: "Confirming transaction",
	}, nil
}

func (s *UtxoServer) QueryDepositAddress(ctx context.Context, req *pb.QueryDepositAddressRequest) (*pb.QueryDepositAddressResponse, error) {
	pubKey, err := s.getPubKey()
	if err != nil {
		return nil, err
	}

	return &pb.QueryDepositAddressResponse{
		DepositAddress: hex.EncodeToString(pubKey),
	}, nil
}
