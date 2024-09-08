package p2p

import (
	"context"
	"encoding/json"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	log "github.com/sirupsen/logrus"
)

func handleHandshake(s network.Stream) {
	buffer := make([]byte, len(expectedHandshake))
	_, err := s.Read(buffer)
	if err != nil {
		log.Errorf("Failed to read handshake data: %v", err)
		return
	}

	if string(buffer) == expectedHandshake {
		log.Info("Handshake successful")
	} else {
		log.Warn("Handshake failed")
		s.Reset()
	}
}

func PublishMessage(ctx context.Context, msg Message) {
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		log.Errorf("Failed to marshal message: %v", err)
		return
	}

	if messageTopic == nil {
		log.Error("Message topic is nil, cannot publish message")
		return
	}

	if err := messageTopic.Publish(ctx, msgBytes); err != nil {
		log.Errorf("Failed to publish message: %v", err)
	}
}

func handlePubSubMessages(ctx context.Context, sub *pubsub.Subscription, node host.Host, signChan chan SignatureMessage) {
	for {
		msg, err := sub.Next(ctx)
		if err != nil {
			log.Errorf("Error reading message from pubsub: %v", err)
			continue
		}

		if msg.ReceivedFrom == node.ID() {
			log.Debug("Received message from self, ignore")
			continue
		}

		var receivedMsg Message
		if err := json.Unmarshal(msg.Data, &receivedMsg); err != nil {
			log.Errorf("Error unmarshaling pubsub message: %v", err)
			continue
		}

		log.Infof("Received message via pubsub: ID=%d, Content=%s", receivedMsg.MessageType, receivedMsg.Content)

		switch receivedMsg.MessageType {
		case MessageTypeSignature:
			sigBytes := []byte(receivedMsg.Content)
			select {
			case signChan <- SignatureMessage{
				PeerID:    msg.ReceivedFrom.String(),
				Signature: sigBytes,
			}:
			default:
				log.Warnf("Unknown message type: %d", receivedMsg.MessageType)
			}
		// case MessageTypeKeygen:
		// 	tssKeyCh <- tss.KeygenMessage{Content: receivedMsg.Content}
		// case MessageTypeSigning:
		// 	tssSignCh <- tss.SigningMessage{Content: receivedMsg.Content}
		default:
			log.Warnf("Unknown message type: %d", receivedMsg.MessageType)
		}
	}
}

func handleHeartbeatMessages(ctx context.Context, sub *pubsub.Subscription, node host.Host) {
	for {
		msg, err := sub.Next(ctx)
		if err != nil {
			log.Errorf("Error reading heartbeat message from pubsub: %v", err)
			continue
		}

		if msg.ReceivedFrom == node.ID() {
			log.Debug("Received heartbeat from self, ignore")
			continue
		}

		var hbMsg HeartbeatMessage
		if err := json.Unmarshal(msg.Data, &hbMsg); err != nil {
			log.Errorf("Error unmarshaling heartbeat message: %v", err)
			continue
		}

		log.Infof("Received heartbeat from %d-%s: %s", hbMsg.Timestamp, hbMsg.PeerID, hbMsg.Message)
	}
}

func startHeartbeat(ctx context.Context, node host.Host, topic *pubsub.Topic) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hbMsg := HeartbeatMessage{
				PeerID:    node.ID().String(),
				Message:   "heartbeat",
				Timestamp: time.Now().Unix(),
			}

			msgBytes, err := json.Marshal(hbMsg)
			if err != nil {
				log.Errorf("Failed to marshal heartbeat message: %v", err)
				continue
			}

			if err := topic.Publish(ctx, msgBytes); err != nil {
				log.Errorf("Failed to publish heartbeat message: %v", err)
			} else {
				log.Infof("Heartbeat message sent by %s", hbMsg.PeerID)
			}

		case <-ctx.Done():
			return
		}
	}
}
