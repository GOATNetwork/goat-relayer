package p2p

import (
	"context"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	tcp "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/multiformats/go-multiaddr"
	log "github.com/sirupsen/logrus"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
)

const (
	handshakeProtocol  = "/goat/voter/handshake/1.0.0"
	messageProtocol    = "/goat/voter/message/1.0.0"
	expectedHandshake  = "goatvotergoatbest"
	messageTopicName   = "gossip-topic"
	heartbeatTopicName = "heartbeat-topic"
	privKeyFile        = "node_private_key.pem"
)

var messageTopic *pubsub.Topic

type LibP2PService struct {
	db       *db.DatabaseManager
	signChan chan SignatureMessage
}

func NewLibP2PService(db *db.DatabaseManager) *LibP2PService {
	return &LibP2PService{
		db:       db,
		signChan: make(chan SignatureMessage),
	}
}

func (lp *LibP2PService) Start(ctx context.Context) {
	// Start libp2p node
	// tssKeyInCh := make(chan tss.KeygenMessage)
	// tssKeyOutCh := make(chan tsslib.Message)
	// tssKeyEndCh := make(chan *keygen.LocalPartySaveData)
	// tssSignInCh := make(chan tss.SigningMessage)
	// tssSignOutCh := make(chan tsslib.Message)
	// tssSignEndCh := make(chan *common.SignatureData)

	node, ps, err := createNodeWithPubSub(ctx)
	if err != nil {
		log.Fatalf("Failed to create libp2p node: %v", err)
	}

	// Print self boot node info
	printNodeAddrInfo(node)

	// Set handshake
	node.SetStreamHandler(protocol.ID(handshakeProtocol), func(s network.Stream) {
		log.Println("New handshake stream")
		handleHandshake(s)
		s.Close()
	})

	bootNodeAddrs := strings.Split(config.AppConfig.Libp2pBootNodes, ",")
	// Connect to bootnodes and handshake
	for _, addr := range bootNodeAddrs {
		if addr == "" {
			continue
		}
		connectToBootNode(ctx, node, addr)
	}

	messageTopic, err = ps.Join(messageTopicName)
	if err != nil {
		log.Fatalf("Failed to join message topic: %v", err)
	}

	sub, err := messageTopic.Subscribe()
	if err != nil {
		log.Fatalf("Failed to subscribe to message topic: %v", err)
	}

	hbTopic, err := ps.Join(heartbeatTopicName)
	if err != nil {
		log.Fatalf("Failed to join heartbeat topic: %v", err)
	}

	hbSub, err := hbTopic.Subscribe()
	if err != nil {
		log.Fatalf("Failed to subscribe to heartbeat topic: %v", err)
	}

	go handlePubSubMessages(ctx, sub, node, lp.signChan)
	go handleHeartbeatMessages(ctx, hbSub, node)
	go startHeartbeat(ctx, node, hbTopic)

	go func() {
		time.Sleep(5 * time.Second)
		msg := Message{
			MessageType: MessageTypeKeygen,
			Content:     "Hello, goat voter libp2p PubSub network with handshake!",
		}
		PublishMessage(ctx, msg)
	}()

	<-ctx.Done()

	log.Info("LibP2PService is stopping...")

	if err := node.Close(); err != nil {
		log.Errorf("Error closing libp2p node: %v", err)
	}

	log.Info("LibP2PService has stopped.")

	// close(tssKeyInCh)
	// close(tssKeyOutCh)
	// close(tssKeyEndCh)
	// close(tssSignInCh)
	// close(tssSignOutCh)
	// close(tssSignEndCh)
}

func createNodeWithPubSub(ctx context.Context) (host.Host, *pubsub.PubSub, error) {
	privKey, err := loadOrCreatePrivateKey(privKeyFile)
	if err != nil {
		return nil, nil, err
	}

	listenAddr := fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", config.AppConfig.Libp2pPort)
	node, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.Transport(tcp.NewTCPTransport), //TCP only
		libp2p.ListenAddrStrings(listenAddr),  // ipv4 only
	)
	if err != nil {
		return nil, nil, err
	}

	ps, err := pubsub.NewGossipSub(ctx, node)
	if err != nil {
		return nil, nil, err
	}

	return node, ps, nil
}

func connectToBootNode(ctx context.Context, node host.Host, bootNodeAddr string) {
	multiAddr, err := multiaddr.NewMultiaddr(bootNodeAddr)
	if err != nil {
		log.Printf("Failed to parse bootnode address: %v", err)
		return
	}

	peerInfo, err := peer.AddrInfoFromP2pAddr(multiAddr)
	if err != nil {
		log.Printf("Failed to get peer info from address: %v", err)
		return
	}

	node.Peerstore().AddAddrs(peerInfo.ID, peerInfo.Addrs, peerstore.PermanentAddrTTL)
	if err := node.Connect(ctx, *peerInfo); err != nil {
		log.Errorf("Failed to connect to bootnode: %v", err)
	} else {
		log.Infof("Connected to bootnode: %s", peerInfo.ID.String())

		// Handshake after connect
		s, err := node.NewStream(ctx, peerInfo.ID, protocol.ID(handshakeProtocol))
		if err != nil {
			log.Errorf("Failed to create handshake stream to peer %s: %v", peerInfo.ID, err)
			return
		}

		_, err = s.Write([]byte(expectedHandshake))
		if err != nil {
			log.Errorf("Failed to send handshake to peer %s: %v", peerInfo.ID, err)
			s.Reset()
			return
		}

		s.Close()
	}
}

func loadOrCreatePrivateKey(fileName string) (crypto.PrivKey, error) {
	dbDir := config.AppConfig.DbDir
	if err := os.MkdirAll(dbDir, os.ModePerm); err != nil {
		log.Fatalf("Failed to create database directory: %v", err)
	}

	pemPath := filepath.Join(dbDir, fileName)
	if _, err := os.Stat(pemPath); err == nil {
		privKeyBytes, err := ioutil.ReadFile(pemPath)
		if err != nil {
			return nil, err
		}
		privKey, err := crypto.UnmarshalPrivateKey(privKeyBytes)
		if err != nil {
			return nil, err
		}
		return privKey, nil
	}

	privKey, _, err := crypto.GenerateKeyPairWithReader(crypto.Ed25519, 2048, rand.Reader)
	if err != nil {
		return nil, err
	}

	privKeyBytes, err := crypto.MarshalPrivateKey(privKey)
	if err != nil {
		return nil, err
	}

	if err := ioutil.WriteFile(pemPath, privKeyBytes, 0600); err != nil {
		return nil, err
	}

	return privKey, nil
}

func printNodeAddrInfo(node host.Host) {
	addrs := node.Addrs()
	peerID := node.ID().String()

	for _, addr := range addrs {
		fullAddr := fmt.Sprintf("%s/p2p/%s", addr, peerID)
		log.Infof("Bootnode address: %s", fullAddr)
	}
}
