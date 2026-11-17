package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseDurationAtLeast(t *testing.T) {
	d, err := parseDurationAtLeast("UTXO_RECONCILE_INTERVAL", " 10m ", time.Minute)
	require.NoError(t, err)
	require.Equal(t, 10*time.Minute, d)

	for _, raw := range []string{"600", "1800", "", "0", "ten minutes"} {
		_, err := parseDurationAtLeast("UTXO_RECONCILE_INTERVAL", raw, time.Minute)
		require.Error(t, err, raw)
	}

	_, err = parseDurationAtLeast("UTXO_RECONCILE_MIN_AGE", "5m", 10*time.Minute)
	require.ErrorContains(t, err, "must be at least 10m0s")
}
