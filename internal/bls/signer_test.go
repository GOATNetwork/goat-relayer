package bls

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	goatcryp "github.com/goatnetwork/goat/pkg/crypto"

	"github.com/stretchr/testify/assert"
)

func generateBLSKeyPair() (string, string) {
	// Generate private key
	var privKeyElement fr.Element
	privKeyElement.SetRandom()
	privKeyBytes := privKeyElement.Bytes()

	// Use goat's method to generate public key
	sk := new(goatcryp.PrivateKey).Deserialize(privKeyBytes[:])
	pk := new(goatcryp.PublicKey).From(sk).Compress()

	// Convert to hexadecimal strings
	privKeyHex := hex.EncodeToString(privKeyBytes[:])
	pubKeyHex := hex.EncodeToString(pk)

	return privKeyHex, pubKeyHex
}

func generateSecp256k1KeyPair() (string, string, error) {
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		return "", "", err
	}

	privKeyBytes := privateKey.Serialize()
	privKeyHex := hex.EncodeToString(privKeyBytes)

	pubKey := privateKey.PubKey()
	pubKeyBytes := pubKey.SerializeCompressed()
	pubKeyHex := hex.EncodeToString(pubKeyBytes)

	return privKeyHex, pubKeyHex, nil
}

func TestBLSPrivateKeyDeserializeAndPublicKeyCompress(t *testing.T) {
	testCases := []struct {
		name          string
		skHex         string
		expectedPKHex string
	}{
		{
			name: "Newly generated BLS key pair 1",
		},
		{
			name: "Newly generated BLS key pair 2",
		},
		{
			name: "Newly generated BLS key pair 3",
		},
	}

	// Generate new BLS key pairs for each test case
	for i := range testCases {
		testCases[i].skHex, testCases[i].expectedPKHex = generateBLSKeyPair()
		fmt.Printf("BLS test case %d:\nPrivate key: %s\nPublic key: %s\n\n", i+1, testCases[i].skHex, testCases[i].expectedPKHex)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Convert hexadecimal string to byte slice
			skBytes, err := hex.DecodeString(tc.skHex)
			assert.NoError(t, err)

			// Deserialize private key
			sk := new(goatcryp.PrivateKey).Deserialize(skBytes)
			assert.NotNil(t, sk)

			// Generate and compress public key from private key
			pk := new(goatcryp.PublicKey).From(sk).Compress()
			assert.NotNil(t, pk)

			// Convert compressed public key to hexadecimal string
			pkHex := hex.EncodeToString(pk)

			// Verify if the generated public key matches the expected one
			assert.Equal(t, tc.expectedPKHex, pkHex)
		})
	}
}

func TestSecp256k1PrivateKeyDeserializeAndPublicKeyCompress(t *testing.T) {
	testCases := []struct {
		name          string
		skHex         string
		expectedPKHex string
	}{
		{
			name: "Newly generated secp256k1 key pair 1",
		},
		{
			name: "Newly generated secp256k1 key pair 2",
		},
		{
			name: "Newly generated secp256k1 key pair 3",
		},
	}

	// Generate new secp256k1 key pairs for each test case
	for i := range testCases {
		var err error
		testCases[i].skHex, testCases[i].expectedPKHex, err = generateSecp256k1KeyPair()
		assert.NoError(t, err)
		fmt.Printf("secp256k1 test case %d:\nPrivate key: %s\nPublic key: %s\n\n", i+1, testCases[i].skHex, testCases[i].expectedPKHex)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Convert hexadecimal string to byte slice
			skBytes, err := hex.DecodeString(tc.skHex)
			assert.NoError(t, err)

			// Deserialize private key
			sk, _ := btcec.PrivKeyFromBytes(skBytes)
			assert.NoError(t, err)
			assert.NotNil(t, sk)

			// Generate and compress public key from private key
			pk := sk.PubKey()
			pkCompressed := pk.SerializeCompressed()
			assert.NotNil(t, pkCompressed)

			// Convert compressed public key to hexadecimal string
			pkHex := hex.EncodeToString(pkCompressed)

			// Verify if the generated public key matches the expected one
			assert.Equal(t, tc.expectedPKHex, pkHex)
		})
	}
}
