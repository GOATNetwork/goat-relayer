package p2p

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/state"

	log "github.com/sirupsen/logrus"
)

// Protocol constants
const (
	ProtocolID   = "/goat-network/goat-relayer/1.0.0"
	DiscoveryTag = "goat-goat-relayer"
	LibP2PTopic  = "goat-goat-relayer-protocol"
)

// Network provides P2P networking functionality
// Network struct remains largely the same

type Network struct {
	state  *state.State
	logger *log.Entry
	host   host.Host
	ps     *pubsub.PubSub
	topic  *pubsub.Topic
	ctx    context.Context
	cancel context.CancelFunc
}

// displayPublicKey prints the node's public key in hex format and PeerID
func displayPublicKey(host host.Host) {
	pub := host.Peerstore().PubKey(host.ID())
	if pub == nil {
		log.Errorf("public key not found in peerstore")
		return
	}
	raw, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		log.Errorf("marshal public key error: %v", err)
		return
	}
	hexKey := hex.EncodeToString(raw)
	log.Debugf("Node PeerID: %s", host.ID().String())
	log.Debugf("Public Key hex: %s", hexKey)
}

// NewNetwork creates and initializes a new P2P network
func NewNetwork(state *state.State) (*Network, error) {
	logger := log.WithFields(log.Fields{
		"module": "p2p",
	})
	priv, err := loadOrCreatePrivateKey(privKeyFile)
	if err != nil {
		return nil, err
	}
	options := []libp2p.Option{
		libp2p.Identity(priv),
	}
	listenAddr := fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", config.AppConfig.Libp2pPort)
	options = append(options, libp2p.ListenAddrStrings(listenAddr))

	addrsOpt := libp2p.AddrsFactory(func(in []multiaddr.Multiaddr) (out []multiaddr.Multiaddr) {
		for _, a := range in {
			if manet.IsPublicAddr(a) || manet.IsPrivateAddr(a) {
				// exclude 0.0.0.0 / 127.0.0.1 / link-local
				if !manet.IsIPLoopback(a) && !manet.IsIP6LinkLocal(a) && !manet.IsIPUnspecified(a) {
					out = append(out, a)
				}
			}
		}
		for _, s := range strings.FieldsFunc(os.Getenv("EXTERNAL_P2P_ADDR"), func(r rune) bool { return r == ',' || r == ' ' }) {
			if m, err := multiaddr.NewMultiaddr(strings.TrimSpace(s)); err == nil {
				out = append(out, m)
			} else {
				log.Warnf("bad multiaddr %q: %v", s, err)
			}
		}
		return
	})
	options = append(options, addrsOpt)

	host, err := libp2p.New(options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	// display pubkey
	displayPublicKey(host)

	// Register protocol handler
	host.SetStreamHandler(protocol.ID(ProtocolID), func(stream network.Stream) {
		defer stream.Close()
		logger.Debugf("Received protocol stream from %s", stream.Conn().RemotePeer())
		// For now, just acknowledge the protocol support
		// In the future, this could handle direct peer-to-peer communication
	})

	ctx := context.Background()
	ps, err := pubsub.NewGossipSub(ctx, host,
		pubsub.WithMessageSignaturePolicy(pubsub.StrictSign),
		pubsub.WithPeerOutboundQueueSize(1000),
		pubsub.WithPeerExchange(true),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub: %w", err)
	}

	topic, err := ps.Join(LibP2PTopic)
	if err != nil {
		return nil, fmt.Errorf("failed to join topic %s: %w", LibP2PTopic, err)
	}

	ctx, cancel := context.WithCancel(ctx)

	n := &Network{
		state:  state,
		logger: logger,
		host:   host,
		ps:     ps,
		topic:  topic,
		ctx:    ctx,
		cancel: cancel,
	}

	go n.handlePubSubMessages()
	go n.startHeartbeat()

	logger.Infof("P2P network initialized with PubSub. Node ID: %s", n.host.ID())
	for _, addr := range n.host.Addrs() {
		logger.Infof("Listening on: %s/p2p/%s", addr, n.host.ID())
	}

	// Log external address if configured
	if externalAddr := os.Getenv("EXTERNAL_P2P_ADDR"); externalAddr != "" {
		logger.Infof("External P2P address configured: %s/p2p/%s", externalAddr, n.host.ID())
	} else {
		logger.Warnf("EXTERNAL_P2P_ADDR not configured. Other nodes may not be able to connect to this bootnode.")
	}

	return n, nil
}

func (n *Network) checkWhitelisted(peerID peer.ID) error {
	// check if the peerID is in the whitelist
	pubKey := n.host.Peerstore().PubKey(peerID)
	if pubKey == nil {
		return fmt.Errorf("public key not found for peer %s", peerID)
	}

	// TODO: check if the peerID is in the whitelist

	return nil
}

func (n *Network) handlePubSubMessages() {
	sub, err := n.topic.Subscribe()
	if err != nil {
		n.logger.Errorf("Failed to subscribe to topic %s: %v", LibP2PTopic, err)
		return
	}
	defer sub.Cancel()

	for {
		select {
		case <-n.ctx.Done():
			return
		default:
		}

		msg, err := sub.Next(n.ctx)
		if err != nil {
			// Check if context was cancelled
			select {
			case <-n.ctx.Done():
				return
			default:
				log.Errorf("Error receiving pubsub message: %v", err)
				continue
			}
		}

		if msg.GetFrom() == n.host.ID() {
			continue
		}
		// Verify signature
		if err := n.checkWhitelisted(msg.GetFrom()); err != nil {
			n.logger.Errorf("Whitelisted check failed: %v", err)
			continue
		}

		var receivedMsg Message[json.RawMessage]
		if err := json.Unmarshal(msg.Data, &receivedMsg); err != nil {
			log.Errorf("Error unmarshaling pubsub message: %v", err)
			continue
		}

		log.Debugf("Received message via pubsub: ID=%d, RequestId=%s, Data=%v", receivedMsg.MessageType, receivedMsg.RequestId, receivedMsg.Data)

		switch receivedMsg.MessageType {
		case MessageTypeSigReq:
			n.state.EventBus.Publish(state.SigReceive, convertMsgData(receivedMsg))
		case MessageTypeSigResp:
			n.state.EventBus.Publish(state.SigReceive, convertMsgData(receivedMsg))
		case MessageTypeDepositReceive:
			n.state.EventBus.Publish(state.DepositReceive, convertMsgData(receivedMsg))
		case MessageTypeSendOrderBroadcasted:
			n.state.EventBus.Publish(state.SendOrderBroadcasted, convertMsgData(receivedMsg))
		case MessageTypeNewVoter:
			n.state.EventBus.Publish(state.NewVoter, convertMsgData(receivedMsg))
		case MessageTypeSafeboxTask:
			n.state.EventBus.Publish(state.SafeboxTask, convertMsgData(receivedMsg))
		case MessageTypeHeartbeat:
			n.logger.Infof("💓 Received heartbeat from %s: %s", msg.GetFrom().String(), unmarshal[string](receivedMsg.Data))
		default:
			log.Warnf("Unknown message type: %d", receivedMsg.MessageType)
		}
	}
}

// Initialize connects to bootstrap peers and sets up mDNS if enabled
func (n *Network) Initialize(ctx context.Context) error {
	bootNodeAddrs := strings.Split(config.AppConfig.Libp2pBootNodes, ",")
	// Connect to bootstrap peers
	if len(bootNodeAddrs) > 0 {
		if err := n.connectToBootstrapPeers(ctx); err != nil {
			return fmt.Errorf("failed to connect to bootstrap peers: %w", err)
		}
	}

	return nil
}

// ID returns the peer ID of this node
func (n *Network) ID() peer.ID {
	return n.host.ID()
}

// Addrs returns the listen addresses of this node as strings
func (n *Network) Addrs() []string {
	addrs := n.host.Addrs()
	result := make([]string, len(addrs))
	for i, addr := range addrs {
		result[i] = addr.String()
	}
	return result
}

func (n *Network) Start() error {
	ctx := context.Background()
	if err := n.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize network: %w", err)
	}
	return nil
}

// Close closes the P2P network
func (n *Network) Close() error {
	n.cancel()
	return n.host.Close()
}

func (n *Network) BroadcastMessage(msg any) error {
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	err = n.topic.Publish(n.ctx, msgBytes)
	if err != nil {
		return fmt.Errorf("failed to publish to topic %s: %w", LibP2PTopic, err)
	}
	n.logger.Infof("✅ %s published message to topic %s", n.host.ID().String(), LibP2PTopic)
	return nil
}

// Connect connects to a specific peer
func (n *Network) Connect(ctx context.Context, peerID peer.ID, addrs []string) error {
	var maddrs []multiaddr.Multiaddr
	for _, addr := range addrs {
		maddr, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			return fmt.Errorf("invalid multiaddr %s: %w", addr, err)
		}
		maddrs = append(maddrs, maddr)
	}

	peerInfo := peer.AddrInfo{
		ID:    peerID,
		Addrs: maddrs,
	}
	return n.host.Connect(ctx, peerInfo)
}

// GetPeers returns all connected peers
func (n *Network) GetPeers() []peer.ID {
	return n.host.Network().Peers()
}

// verifyPeerProtocol verifies if a peer supports our protocol
func (n *Network) verifyPeerProtocol(ctx context.Context, peerID peer.ID) bool {
	// First check if the peer is in our topic (PubSub-based communication)
	if n.topic != nil {
		topicPeers := n.topic.ListPeers()
		for _, topicPeer := range topicPeers {
			if topicPeer == peerID {
				n.logger.Debugf("Peer %s is in our topic, considering it compatible", peerID)
				return true
			}
		}
	}

	// Check if the peer has our protocol in their peerstore
	protocols, err := n.host.Peerstore().GetProtocols(peerID)
	if err != nil {
		n.logger.Debugf("Failed to get protocols for peer %s: %v", peerID, err)
	} else {
		for _, proto := range protocols {
			if string(proto) == ProtocolID {
				n.logger.Debugf("Peer %s supports our protocol %s", peerID, ProtocolID)
				return true
			}
		}
	}

	// Try to establish a stream connection to verify protocol support
	stream, err := n.host.NewStream(ctx, peerID, protocol.ID(ProtocolID))
	if err != nil {
		n.logger.Debugf("Peer %s does not support protocol %s: %v", peerID, ProtocolID, err)
		return false
	}
	stream.Close()

	return true
}

// startHeartbeat starts the heartbeat mechanism to maintain connections
func (n *Network) startHeartbeat() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			peers := n.GetPeers()
			topicPeers := []peer.ID{}
			if n.topic != nil {
				topicPeers = n.topic.ListPeers()
			}
			n.logger.Infof("Heartbeat: Currently connected to %d peers, %d topic peers", len(peers), len(topicPeers))

			// If no peers connected, try to reconnect to bootstrap peers
			if len(peers) == 0 {
				n.logger.Warnf("No peers connected, attempting to reconnect to bootstrap peers...")
				bootNodeAddrs := strings.Split(config.AppConfig.Libp2pBootNodes, ",")
				validAddrs := []string{}
				for _, addr := range bootNodeAddrs {
					addr = strings.TrimSpace(addr)
					if addr != "" {
						validAddrs = append(validAddrs, addr)
					}
				}
				if len(validAddrs) > 0 {
					if err := n.connectToBootstrapPeers(n.ctx); err != nil {
						n.logger.Errorf("Failed to reconnect to bootstrap peers: %v", err)
					}
				} else {
					n.logger.Warnf("No valid bootstrap peer addresses configured for reconnection")
				}
			} else {
				unixnano := time.Now().UnixNano()
				msg := Message[any]{
					RequestId:   fmt.Sprintf("hb-%d", unixnano),
					MessageType: MessageTypeHeartbeat,
					Data:        fmt.Sprintf("Heartbeat from %s, my unixnano is %d", n.host.ID().String(), unixnano),
				}
				n.BroadcastMessage(msg)
			}
		}
	}
}

// connectToBootstrapPeers connects to the provided bootstrap peers
func (n *Network) connectToBootstrapPeers(ctx context.Context) error {
	successfulConnections := 0
	bootNodeAddrs := strings.Split(config.AppConfig.Libp2pBootNodes, ",")

	// Check if we have any valid bootstrap addresses
	validAddrs := []string{}
	for _, addr := range bootNodeAddrs {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			validAddrs = append(validAddrs, addr)
		}
	}

	if len(validAddrs) == 0 {
		n.logger.Warnf("No valid bootstrap peer addresses configured. Set LIBP2P_BOOT_NODES environment variable to connect to other nodes.")
		return fmt.Errorf("no valid bootstrap peer addresses configured")
	}

	for _, peerAddr := range validAddrs {
		addr, err := multiaddr.NewMultiaddr(peerAddr)
		if err != nil {
			n.logger.Errorf("Failed to parse bootstrap peer address %s: %v", peerAddr, err)
			continue
		}

		peerInfo, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			n.logger.Errorf("Failed to get peer info from address %s: %v", peerAddr, err)
			continue
		}

		// Skip self connection
		if peerInfo.ID == n.host.ID() {
			n.logger.Debugf("Skipping self connection to bootstrap peer: %s", peerInfo.ID)
			continue
		}

		// Store bootstrap peer metadata (mark as bootstrap peer for discovery tag verification)
		n.host.Peerstore().Put(peerInfo.ID, "peer-type", "bootstrap")

		if err := n.host.Connect(ctx, *peerInfo); err != nil {
			n.logger.Errorf("Failed to connect to bootstrap peer %s: %v", peerInfo.ID, err)
			continue
		}

		// Try to verify the peer supports our protocol, but don't disconnect if it doesn't
		// as PubSub communication might still work
		verifyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if n.verifyPeerProtocol(verifyCtx, peerInfo.ID) {
			n.logger.Infof("Successfully connected to bootstrap peer: %s with protocol support", peerInfo.ID)
		} else {
			n.logger.Warnf("Bootstrap peer %s does not support our protocol %s, but keeping connection for PubSub", peerInfo.ID, ProtocolID)
		}
		cancel()

		n.logger.Infof("Successfully connected to bootstrap peer: %s", peerInfo.ID)
		successfulConnections++
	}

	if successfulConnections == 0 {
		return fmt.Errorf("failed to connect to any bootstrap peers")
	}

	return nil
}
