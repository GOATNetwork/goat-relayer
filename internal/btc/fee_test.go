package btc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetMempoolFeeRate(t *testing.T) {
	// mock HTTP response
	mockResponse := MempoolFeesResp{
		FastestFee:  50,
		HalfHourFee: 30,
		HourFee:     10,
	}

	// create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	// create MemPoolFeeFetcher and replace URL
	fetcher := &MemPoolFeeFetcher{httpClient: server.Client()}
	// call getFeeRate method
	feeRate, err := fetcher.getFeeRate(server.URL)
	assert.NoError(t, err)

	// assert
	assert.Equal(t, mockResponse.FastestFee, feeRate.FastestFee)
	assert.Equal(t, mockResponse.HalfHourFee, feeRate.HalfHourFee)
	assert.Equal(t, mockResponse.HourFee, feeRate.HourFee)
}
