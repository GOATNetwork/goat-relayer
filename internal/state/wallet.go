package state

import (
	"github.com/goatnetwork/goat-relayer/internal/db"
	log "github.com/sirupsen/logrus"
)

func (s *State) UpdateUTXO(utxo *db.Utxo) error {
	s.walletMu.Lock()
	defer s.walletMu.Unlock()

	err := s.saveUTXO(utxo)
	if err != nil {
		return err
	}

	return nil
}

func (s *State) saveUTXO(utxo *db.Utxo) error {
	result := s.dbm.GetWalletDB().Save(utxo)
	if result.Error != nil {
		log.Errorf("State saveUTXO error: %v", result.Error)
		return result.Error
	}
	s.walletState.Utxo = utxo
	return nil
}
