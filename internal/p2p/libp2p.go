package p2p

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	tcp "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/multiformats/go-multiaddr"
	log "github.com/sirupsen/logrus"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/state"
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
	state *state.State
}

func NewLibP2PService(state *state.State) *LibP2PService {
	return &LibP2PService{
		state: state,
	}
}

func (lp *LibP2PService) Start(ctx context.Context) {
	node, ps, err := createNodeWithPubSub(ctx)
	if err != nil {
		log.Fatalf("Failed to create libp2p node: %v", err)
	}
	printNodeAddrInfo(node)

	node.SetStreamHandler(protocol.ID(handshakeProtocol), func(s network.Stream) {
		log.Println("New handshake stream")
		handleHandshake(s, node)
		s.Close()
	})

	go lp.connectToBootNodes(ctx, node)

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

	go lp.handlePubSubMessages(ctx, sub, node)
	go lp.handleHeartbeatMessages(ctx, hbSub, node)
	go startHeartbeat(ctx, node, hbTopic)

	go func() {
		time.Sleep(5 * time.Second)
		msg := Message{
			RequestId:   "1",
			MessageType: MessageTypeUnknown,
			Data:        "Hello, goat voter libp2p PubSub network with handshake!",
		}
		PublishMessage(ctx, msg)
	}()

	<-ctx.Done()

	log.Info("LibP2PService is stopping...")
	if err := node.Close(); err != nil {
		log.Errorf("Error closing libp2p node: %v", err)
	}
	log.Info("LibP2PService has stopped.")
}

func (lp *LibP2PService) connectToBootNodes(ctx context.Context, node host.Host) {
	bootNodeAddrs := strings.Split(config.AppConfig.Libp2pBootNodes, ",")
	var wg sync.WaitGroup

	for _, addr := range bootNodeAddrs {
		if addr == "" {
			continue
		}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					log.Infof("Context cancelled, stopping connection attempts to %s", addr)
					return
				default:
					err := lp.connectToBootNode(ctx, node, addr)
					if err != nil {
						log.Errorf("Failed to connect to bootnode %s: %v", addr, err)
						time.Sleep(10 * time.Second)
					} else {
						log.Infof("Successfully connected to bootnode %s", addr)
						lp.monitorConnection(ctx, node, addr)
						return
					}
				}
			}
		}(addr)
	}

	wg.Wait()
}

func (lp *LibP2PService) connectToBootNode(ctx context.Context, node host.Host, addr string) error {
	peerInfo, err := parseAddr(addr)
	if err != nil {
		return fmt.Errorf("failed to parse bootnode address %s: %v", addr, err)
	}

	if err := node.Connect(ctx, *peerInfo); err != nil {
		return fmt.Errorf("failed to connect to bootnode %s: %v", addr, err)
	}

	s, err := node.NewStream(ctx, peerInfo.ID, protocol.ID(handshakeProtocol))
	if err != nil {
		return fmt.Errorf("failed to create handshake stream with %s: %v", addr, err)
	}
	defer s.Close()

	err = sendHandshake(s)
	if err != nil {
		return fmt.Errorf("failed to send handshake to %s: %v", addr, err)
	}

	return nil
}

func (lp *LibP2PService) monitorConnection(ctx context.Context, node host.Host, addr string) {
	peerInfo, err := parseAddr(addr)
	if err != nil {
		log.Errorf("Failed to parse bootnode address %s: %v", addr, err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			log.Infof("Context cancelled, stopping monitoring of %s", addr)
			return
		default:
			if node.Network().Connectedness(peerInfo.ID) != network.Connected {
				log.Warnf("Disconnected from %s, attempting to reconnect", addr)
				err := lp.connectToBootNode(ctx, node, addr)
				if err != nil {
					log.Errorf("Failed to reconnect to %s: %v", addr, err)
					time.Sleep(5 * time.Second)
					continue
				}
				log.Infof("Successfully reconnected to %s", addr)
			}
			time.Sleep(20 * time.Second)
		}
	}
}

func parseAddr(addrStr string) (*peer.AddrInfo, error) {
	addr, err := multiaddr.NewMultiaddr(addrStr)
	if err != nil {
		return nil, err
	}
	return peer.AddrInfoFromP2pAddr(addr)
}

func sendHandshake(s network.Stream) error {
	handshakeMsg := []byte(expectedHandshake)

	_, err := s.Write(handshakeMsg)
	if err != nil {
		return err
	}

	// verify handshake
	buf := make([]byte, len(handshakeMsg))
	_, err = s.Read(buf)
	if err != nil {
		return err
	}

	if !bytes.Equal(buf, handshakeMsg) {
		return fmt.Errorf("invalid handshake response")
	}

	return nil
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
