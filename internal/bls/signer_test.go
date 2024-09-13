package bls

import (
	"encoding/hex"
	"testing"

	goatcryp "github.com/goatnetwork/goat/pkg/crypto"

	"github.com/stretchr/testify/assert"
)

func TestBlsTwoAggregate(t *testing.T) {
	sk1 := goatcryp.GenPrivKey()
	sk2 := goatcryp.GenPrivKey()

	t.Logf("sk1: %s, sk2: %s", hex.EncodeToString(sk1.Serialize()), hex.EncodeToString(sk2.Serialize()))

	pk1 := new(goatcryp.PublicKey).From(sk1).Compress()
	pk2 := new(goatcryp.PublicKey).From(sk2).Compress()

	t.Logf("pk1: %s, pk2: %s", hex.EncodeToString(pk1), hex.EncodeToString(pk2))

	// Prepare the message to be signed
	message := []byte("Hello, world!")

	sig1 := goatcryp.Sign(sk1, message)
	sig2 := goatcryp.Sign(sk2, message)

	aggSig, err := goatcryp.AggregateSignatures([][]byte{sig1, sig2})

	assert.NoError(t, err, "agg sig")

	verified := goatcryp.AggregateVerify([][]byte{pk1, pk2}, message, aggSig)
	assert.True(t, verified)
}
