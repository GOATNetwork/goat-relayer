package btc

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/types"
	log "github.com/sirupsen/logrus"
)

type NetworkFeeFetcher interface {
	GetNetworkFee() (*types.BtcNetworkFee, error)
}

type MempoolFeesResp struct {
	FastestFee  uint64 `json:"fastestFee"`
	HalfHourFee uint64 `json:"halfHourFee"`
	HourFee     uint64 `json:"hourFee"`
	EconomyFee  uint64 `json:"economyFee"`
	MinimumFee  uint64 `json:"minimumFee"`
}

type MemPoolFeeFetcher struct {
	btcClient  *rpcclient.Client
	httpClient *http.Client
}

func NewMemPoolFeeFetcher(btcClient *rpcclient.Client) *MemPoolFeeFetcher {
	return &MemPoolFeeFetcher{btcClient: btcClient, httpClient: &http.Client{Timeout: 30 * time.Second}}
}

func (f *MemPoolFeeFetcher) GetNetworkFee() (*types.BtcNetworkFee, error) {
	if f.btcClient == nil {
		return nil, errors.New("btc client is not set")
	}
	network := types.GetBTCNetwork(config.AppConfig.BTCNetworkType)
	var url string
	if network == &chaincfg.MainNetParams {
		url = "https://mempool.space/api/v1/fees/recommended"
	} else if network == &chaincfg.TestNet3Params {
		url = "https://mempool.space/testnet/api/v1/fees/recommended"
	}
	if len(url) == 0 {
		return getFeeRateFromBtcNode(f.btcClient)
	}
	fee, err := f.getFeeRate(url)
	if err != nil {
		log.Errorf("Failed to get fee rate from mempool, using btc node: %v", err)
		return getFeeRateFromBtcNode(f.btcClient)
	}
	return fee, nil
}

func (f *MemPoolFeeFetcher) getFeeRate(url string) (*types.BtcNetworkFee, error) {
	resp, err := f.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var feeResp MempoolFeesResp
	if err := json.NewDecoder(resp.Body).Decode(&feeResp); err != nil {
		return nil, err
	}

	return &types.BtcNetworkFee{
		FastestFee:  feeResp.FastestFee,
		HalfHourFee: feeResp.HalfHourFee,
		HourFee:     feeResp.HourFee,
	}, nil
}

// get fee rate from btc node
func getFeeRateFromBtcNode(btcClient *rpcclient.Client) (*types.BtcNetworkFee, error) {
	feeEstimate, err := btcClient.EstimateSmartFee(1, nil)
	if err != nil || feeEstimate == nil || feeEstimate.FeeRate == nil {
		return nil, err
	}
	fastestFee := uint64((*feeEstimate.FeeRate * 1e8) / 1000)

	feeEstimate, err = btcClient.EstimateSmartFee(3, nil)
	if err != nil || feeEstimate == nil || feeEstimate.FeeRate == nil {
		return nil, err
	}
	halfHourFee := uint64((*feeEstimate.FeeRate * 1e8) / 1000)

	feeEstimate, err = btcClient.EstimateSmartFee(6, nil)
	if err != nil || feeEstimate == nil || feeEstimate.FeeRate == nil {
		return nil, err
	}
	hourFee := uint64((*feeEstimate.FeeRate * 1e8) / 1000)

	return &types.BtcNetworkFee{
		FastestFee:  fastestFee,
		HalfHourFee: halfHourFee,
		HourFee:     hourFee,
	}, nil
}
