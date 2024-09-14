package bls

import (
	"context"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/layer2"
	"github.com/goatnetwork/goat-relayer/internal/p2p"
	"github.com/goatnetwork/goat-relayer/internal/state"
	goatcryp "github.com/goatnetwork/goat/pkg/crypto"
)

type Signer struct {
	sk      *goatcryp.PrivateKey
	pk      []byte
	pkHex   string
	address string

	state          *state.State
	libp2p         *p2p.LibP2PService
	layer2Listener *layer2.Layer2Listener

	sigStartCh   chan interface{}
	sigReceiveCh chan interface{}

	// [request_id][vote_address]MsgSign
	sigMap        map[string]map[string]interface{}
	sigTimeoutMap map[string]time.Time
	sigMu         sync.RWMutex
}

func NewSigner(libp2p *p2p.LibP2PService, layer2Listener *layer2.Layer2Listener, state *state.State) *Signer {
	byt, err := hex.DecodeString(config.AppConfig.RelayerBlsSk)
	if err != nil {
		log.Fatalf("Decode bls sk error: %v", err)
	}

	sk := new(goatcryp.PrivateKey).Deserialize(byt)
	pk := new(goatcryp.PublicKey).From(sk).Compress()
	pkHex := hex.EncodeToString(pk)
	log.Infof("Signer init, bls pk: %s, voter address: %s", pkHex, config.AppConfig.RelayerAddress)

	// epoch := state.GetEpochVoter()

	return &Signer{
		sk:      sk,
		pk:      pk,
		pkHex:   pkHex,
		address: config.AppConfig.RelayerAddress,

		state:          state,
		libp2p:         libp2p,
		layer2Listener: layer2Listener,

		sigStartCh:   make(chan interface{}, 256),
		sigReceiveCh: make(chan interface{}, 1024),

		sigMap:        make(map[string]map[string]interface{}),
		sigTimeoutMap: make(map[string]time.Time),
	}
}

func (s *Signer) Start(ctx context.Context) {
	s.state.EventBus.Subscribe(state.SigStart, s.sigStartCh)
	s.state.EventBus.Subscribe(state.SigReceive, s.sigReceiveCh)

	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Info("Signer stoping...")
				return
			case event := <-s.sigStartCh:
				log.Debugf("Received sigStart event: %v", event)
				s.handleSigStart(ctx, event)
			case event := <-s.sigReceiveCh:
				log.Debugf("Received sigReceive event: %v", event)
				s.handleSigReceive(ctx, event)
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Info("Timeout checker stopping...")
				return
			case <-ticker.C:
				s.checkTimeouts()
			}
		}
	}()
}

func (s *Signer) IsProposer() bool {
	epoch := s.state.GetEpochVoter()
	return strings.EqualFold(s.address, epoch.Proposer)
}

func (s *Signer) CanSign() bool {
	l2Info := s.state.GetL2Info()
	return !l2Info.Syncing
}
