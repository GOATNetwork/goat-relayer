package rpc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/goatnetwork/goat-relayer/internal/state"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/goatnetwork/goat-relayer/internal/btc"
	"github.com/goatnetwork/goat-relayer/internal/config"
	pb "github.com/goatnetwork/goat-relayer/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	log "github.com/sirupsen/logrus"
)

type UTXOService interface {
	StartUTXOService(btc.BTCListener)
}

type UTXOServiceImpl struct {
	btc.BTCListener
}

func (us *UTXOServiceImpl) StartUTXOService(btcListener btc.BTCListener) {
	us.BTCListener = btcListener

	addr := ":" + config.AppConfig.HTTPPort
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterBitcoinLightWalletServer(s, &UtxoServer{})
	reflection.Register(s)

	log.Infof("gRPC server is running on port %s", config.AppConfig.HTTPPort)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

type UtxoServer struct {
	pb.UnimplementedBitcoinLightWalletServer
	state *state.State
}

func NewUtxoServer(layer2State *state.State) *UtxoServer {
	return &UtxoServer{
		state: layer2State,
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

	s.state.AddUnconfirmDeposit(req.TransactionId, hex.EncodeToString(req.RawTransaction), hex.EncodeToString(req.EvmAddress))

	// TODO: p2p broadcast, build message
	// p2pMsg := p2p.Message{
	// 	MessageType: p2p.MessageTypeDepositReceive,
	// 	RequestId:   e.RequestId,
	// 	Data:        e.Deposit,
	// }
	// p2p.PublishMessage(ctx, p2pMsg)

	// TODO send Deposit to channel or eventbus -> UnconfirmedChannel Deposit(TxHash + RawTx + EvmAddress)

	// TODO should save this when submit to consensus
	// txid := tx.TxHash().String()
	// evmAddress := common.BytesToAddress(req.EvmAddress).String()

	// utxo := &db.Utxo{
	// 	Uid:       "",
	// 	Txid:      txid,
	// 	OutIndex:  0,
	// 	Amount:    0,
	// 	Receiver:  "",
	// 	Sender:    "",
	// 	EvmAddr:   evmAddress,
	// 	Source:    "deposit",
	// 	Status:    "confirmed",
	// 	UpdatedAt: time.Now(),
	// }

	// err := s.state.UpdateUTXO(utxo)
	// if err != nil {
	// 	return nil, err
	// }

	return &pb.NewTransactionResponse{
		ErrorMessage: "Confirming transaction",
	}, nil
}

func (s *UtxoServer) QueryDepositAddress(ctx context.Context, req *pb.QueryDepositAddressRequest) (*pb.QueryDepositAddressResponse, error) {
	l2Info := s.state.GetL2Info()

	publicKey, err := hex.DecodeString(l2Info.DepositKey)
	if err != nil {
		return nil, err
	}

	network := &chaincfg.MainNetParams
	p2wpkh, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(publicKey), network)
	if err != nil {
		return nil, err
	}

	return &pb.QueryDepositAddressResponse{
		DepositAddress: p2wpkh.EncodeAddress(),
	}, nil
}
