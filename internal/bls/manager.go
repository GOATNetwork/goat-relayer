package bls

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/goatnetwork/goat-relayer/internal/p2p"
	blst "github.com/supranational/blst/bindings/go"
)

type SignatureHelper struct {
	mu         sync.Mutex
	sk         *blst.SecretKey
	pk         *blst.P2Affine
	signatures map[string]*blst.P1Affine
	threshold  int

	signatureChan <-chan p2p.SignatureMessage
}

func NewSignatureHelper(threshold int) (*SignatureHelper, error) {
	ikm := make([]byte, 32)
	if _, err := rand.Read(ikm); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %v", err)
	}
	sk := blst.KeyGen(ikm)
	pk := new(blst.P2Affine).From(sk)

	return &SignatureHelper{
		sk:            sk,
		pk:            pk,
		signatures:    make(map[string]*blst.P1Affine),
		threshold:     threshold,
		signatureChan: make(chan p2p.SignatureMessage),
	}, nil
}

func (sm *SignatureHelper) SignDoc(ctx context.Context, signBytes []byte) *blst.P1Affine {
	sm.broadcastSignature("", signBytes)
	for {
		select {
		case sigMsg := <-sm.signatureChan:
			signature := new(blst.P1Affine).Uncompress(sigMsg.Signature)
			sm.addSignature(sigMsg.PeerID, signature)
			if len(sm.signatures) >= sm.threshold {
				aggregatedSig := sm.aggregateSignatures()
				return aggregatedSig
			}

		case <-ctx.Done():
			return nil
		}
	}
}

func (sm *SignatureHelper) sign(message []byte) *blst.P1Affine {
	return new(blst.P1Affine).Sign(sm.sk, message, []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"))
}

func (sm *SignatureHelper) broadcastSignature(id string, message []byte) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sig := sm.sign(message)
	sigBytes := sig.Compress()

	// Create a message containing the signature information
	msg := p2p.Message{
		MessageType: p2p.MessageTypeSignature,
		Content:     string(sigBytes),
	}

	// Use the p2p module to broadcast the message
	p2p.PublishMessage(context.Background(), msg)

	return sm.addSignature(id, sig)
}

func (sm *SignatureHelper) addSignature(peerID string, sig *blst.P1Affine) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.signatures[peerID] = sig

	return nil
}

func (sm *SignatureHelper) aggregateSignatures() *blst.P1Affine {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sigs := make([]*blst.P1Affine, 0, len(sm.signatures))
	for _, sig := range sm.signatures {
		sigs = append(sigs, sig)
	}

	if len(sigs) == 0 {
		return nil
	}

	// TODO: affine aggregation
	// aggSig := blst.P1sToAffine(sigs)
	return sigs[0]
}
