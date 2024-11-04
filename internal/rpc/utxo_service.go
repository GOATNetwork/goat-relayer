package rpc

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"slices"
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

	evmAddresses, err := splitEvmAddresses(req.EvmAddress)
	if err != nil {
		log.Errorf("Failed to split evm addresses: %v", err)
		return nil, err
	}

	for _, evmAddr := range evmAddresses {
		isTrue, signVersion, outIdxToAmount, err := s.VerifyDeposit(tx, evmAddr)
		if err != nil || !isTrue {
			log.Errorf("Failed to verify deposit: %v", err)
			return nil, err
		}

		for outIdx, amount := range outIdxToAmount {
			isDeposit, err := s.layer2Listener.IsDeposit(tx.TxHash(), uint32(outIdx))
			if err != nil {
				log.Errorf("Failed to check if deposit is already in layer2: %v", err)
				continue
			}
			if isDeposit {
				log.Infof("Deposit is already in layer2: %s", tx.TxHash().String())
				continue
			}

			err = s.state.AddUnconfirmDeposit(req.TransactionId, req.RawTransaction, evmAddr, signVersion, outIdx, amount)
			if err != nil {
				log.Errorf("Failed to add unconfirmed deposit: %v", err)
				continue
			}
			deposit := types.MsgUtxoDeposit{
				RawTx:       req.RawTransaction,
				TxId:        req.TransactionId,
				EvmAddr:     evmAddr,
				SignVersion: signVersion,
				OutputIndex: outIdx,
				Amount:      amount,
				Timestamp:   time.Now().Unix(),
			}

			err = p2p.PublishMessage(context.Background(), p2p.Message[any]{
				MessageType: p2p.MessageTypeDepositReceive,
				RequestId:   fmt.Sprintf("DEPOSIT:%s:%s_%d", config.AppConfig.RelayerAddress, deposit.TxId, outIdx),
				DataType:    "MsgUtxoDeposit",
				Data:        deposit,
			})
			if err != nil {
				log.Errorf("Failed to publish deposit message: %v", err)
				continue
			}
		}
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

func splitEvmAddresses(evmAddressesStr string) ([]string, error) {
	evmAddresses := strings.Split(evmAddressesStr, ",")
	if len(evmAddresses) > 150 {
		return nil, fmt.Errorf("EVM addresses should not be more than 150")
	}

	for i, addr := range evmAddresses {
		evmAddresses[i] = strings.ToLower(strings.TrimPrefix(addr, "0x"))
	}
	slices.Sort(evmAddresses)
	return slices.Compact(evmAddresses), nil
}
