package btc

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/stretchr/testify/require"
)

func newFakeGetTxOutService(t *testing.T, result string) (*BTCRPCService, *[]json.RawMessage) {
	t.Helper()
	var gotParams []json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
			ID     json.RawMessage   `json:"id"`
		}
		require.NoError(t, json.Unmarshal(body, &req))
		require.Equal(t, "gettxout", req.Method)
		gotParams = req.Params
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":` + result + `,"error":null,"id":` + string(req.ID) + `}`))
	}))
	t.Cleanup(server.Close)

	client, err := rpcclient.New(&rpcclient.ConnConfig{
		Host:         strings.TrimPrefix(server.URL, "http://"),
		User:         "x",
		Pass:         "x",
		HTTPPostMode: true,
		DisableTLS:   true,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(client.Shutdown)
	return NewBTCRPCService(client), &gotParams
}

func TestGetTxOutUnspent(t *testing.T) {
	service, params := newFakeGetTxOutService(t, `{"bestblock":"00000000000000000001ae53","confirmations":340,"value":0.28153287,"scriptPubKey":{"hex":"0014"},"coinbase":false}`)

	txOut, err := service.GetTxOut("ed054eeaaef87a7bb6529d953ddd0c8d4885df7257ea34549eb56c5b7474ddeb", 1, true)

	require.NoError(t, err)
	require.NotNil(t, txOut)
	require.Equal(t, int64(340), txOut.Confirmations)
	require.Equal(t, 0.28153287, txOut.Value)
	require.Equal(t, []string{`"ed054eeaaef87a7bb6529d953ddd0c8d4885df7257ea34549eb56c5b7474ddeb"`, `1`, `true`},
		[]string{string((*params)[0]), string((*params)[1]), string((*params)[2])})
}

func TestGetTxOutSpentReturnsNil(t *testing.T) {
	service, _ := newFakeGetTxOutService(t, `null`)

	txOut, err := service.GetTxOut("38b82cf5", 1, true)

	require.NoError(t, err)
	require.Nil(t, txOut)
}
