package http

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const (
	fireblocksBaseAPI = "https://api.fireblocks.io"
)

type FireblocksProposal struct {
	Bip44AddressIndex uint32
	Bip44Change       uint32
	DerivationPath    [5]uint32
	VaultAccountId    string
	AssetId           string

	httpClient *http.Client
}

func NewFireblocksProposal() *FireblocksProposal {
	// use HDWallet 44/1/1/0/0, VaultAccountId:1
	assetId := "BTC_TEST"
	vaultAccountId := "1"
	if types.GetBTCNetwork(config.AppConfig.BTCNetworkType).Name == "mainnet" {
		assetId = "BTC"
		vaultAccountId = "6"
	}
	id, _ := strconv.ParseUint(vaultAccountId, 10, 32)
	vaultAccountIdInt := uint32(id)

	return &FireblocksProposal{
		Bip44AddressIndex: 1,
		Bip44Change:       0,
		DerivationPath:    [5]uint32{44, 1, vaultAccountIdInt, 0, 0},
		VaultAccountId:    vaultAccountId,
		AssetId:           assetId,

		httpClient: &http.Client{},
	}
}

// PostRawSigningRequest posts a raw signing request to fireblocks
func (p *FireblocksProposal) PostRawSigningRequest(unsignedVouts [][]byte, note string) (*FbCreateTransactionResponse, error) {
	messages := make([]FbUnsignedRawMessage, len(unsignedVouts))
	for i, vout := range unsignedVouts {
		messages[i] = FbUnsignedRawMessage{Content: hex.EncodeToString(vout[:])}
	}
	req := &FbCreateTransactionRequest{
		Operation: "RAW",
		Source: FbSource{
			Type: "VAULT_ACCOUNT",
			ID:   p.VaultAccountId,
		},
		AssetID: p.AssetId,
		ExtraParameters: &FbExtraParameters{
			RawMessageData: FbRawMessageData{
				Messages: messages,
			},
		},
		Note: note,
	}

	log.Infof("PostRawSigningRequest to fireblocks: %+v", req)

	respBody, err := p.request("POST", "/v1/transactions", req)
	if err != nil {
		return nil, fmt.Errorf("error posting raw signing request: %v", err)
	}
	var resp FbCreateTransactionResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %v", err)
	}

	return &resp, nil
}

// QueryTransaction queries the transaction on fireblocks
func (p *FireblocksProposal) QueryTransaction(txid string) (*TransactionDetails, error) {
	path := fmt.Sprintf("/v1/transactions/%s", txid)
	respBody, err := p.request("GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("error querying transaction: %v", err)
	}
	var resp TransactionDetails
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %v", err)
	}
	return &resp, nil
}

// request is a helper function to send a request to fireblocks
func (p *FireblocksProposal) request(method, path string, body interface{}) ([]byte, error) {
	var reqBodyBytes []byte
	if body != nil {
		var err error
		reqBodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("error marshaling request body: %v", err)
		}
	}

	rsaPrivKey, err := types.ParseRSAPrivateKeyFromPEM(config.AppConfig.FireblocksSecret)
	if err != nil {
		return nil, fmt.Errorf("error parsing RSA private key: %v", err)
	}

	if config.AppConfig.FireblocksApiKey == "" {
		return nil, fmt.Errorf("fireblocks api key is not set")
	}

	url := fmt.Sprintf("%s%s", fireblocksBaseAPI, path)

	h := sha256.New()
	h.Write(reqBodyBytes)
	reqBodyHash := h.Sum(nil)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"uri":      path,
		"nonce":    uuid.New().String(),
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Minute * 1).Unix(),
		"sub":      config.AppConfig.FireblocksApiKey,
		"bodyHash": hex.EncodeToString(reqBodyHash),
	})
	signedToken, err := token.SignedString(rsaPrivKey)
	if err != nil {
		return nil, fmt.Errorf("error signing JWT token: %v", err)
	}
	req, err := http.NewRequest(method, url, bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP request: %v", err)
	}
	defer req.Body.Close()

	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", signedToken))
	req.Header.Set("X-API-KEY", config.AppConfig.FireblocksApiKey)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending HTTP request: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	return respBody, nil
}
