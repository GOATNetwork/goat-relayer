package http

import "encoding/json"

// FireblocksWebhookRequest
type FireblocksWebhookRequest struct {
	Type      string          `json:"type"`
	TenantId  string          `json:"tenantId"`
	Timestamp int64           `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

// SUBMITTED PENDING_AML_SCREENING PENDING_ENRICHMENT PENDING_AUTHORIZATION QUEUED PENDING_SIGNATURE
// PENDING_3RD_PARTY_MANUAL_APPROVAL PENDING_3RD_PARTY BROADCASTING COMPLETED CONFIRMING
// CANCELLING CANCELLED BLOCKED REJECTED FAILED
type TransactionDetails struct {
	ID                            string                   `json:"id"`
	ExternalTxID                  string                   `json:"externalTxId"`
	Status                        string                   `json:"status"`
	SubStatus                     string                   `json:"subStatus"`
	TxHash                        string                   `json:"txHash,omitempty"`
	Operation                     string                   `json:"operation"`
	Note                          string                   `json:"note"`
	AssetID                       string                   `json:"assetId"`
	AssetType                     string                   `json:"assetType"`
	Source                        TransferPeerPathResponse `json:"source"`
	SourceAddress                 string                   `json:"sourceAddress,omitempty"`
	Destination                   TransferPeerPathResponse `json:"destination"`
	Destinations                  []DestinationsResponse   `json:"destinations,omitempty"`
	DestinationAddress            string                   `json:"destinationAddress,omitempty"`
	DestinationAddressDescription string                   `json:"destinationAddressDescription,omitempty"`
	DestinationTag                string                   `json:"destinationTag,omitempty"`
	AmountInfo                    AmountInfo               `json:"amountInfo"`
	TreatAsGrossAmount            bool                     `json:"treatAsGrossAmount"`
	FeeInfo                       FeeInfo                  `json:"feeInfo"`
	FeeCurrency                   string                   `json:"feeCurrency"`
	CreatedAt                     int64                    `json:"createdAt"`
	LastUpdated                   int64                    `json:"lastUpdated"`
	CreatedBy                     string                   `json:"createdBy"`
	SignedBy                      []string                 `json:"signedBy,omitempty"`
	RejectedBy                    string                   `json:"rejectedBy,omitempty"`
	ExchangeTxID                  string                   `json:"exchangeTxId,omitempty"`
	CustomerRefID                 string                   `json:"customerRefId,omitempty"`
	ReplacedTxHash                string                   `json:"replacedTxHash,omitempty"`
	NumOfConfirmations            int                      `json:"numOfConfirmations"`
	BlockInfo                     BlockInfo                `json:"blockInfo"`
	Index                         int                      `json:"index,omitempty"`
	SystemMessages                []SystemMessageInfo      `json:"systemMessages,omitempty"`
	AddressType                   string                   `json:"addressType,omitempty"`
	RequestedAmount               float64                  `json:"requestedAmount,omitempty"`
	Amount                        float64                  `json:"amount,omitempty"`
	NetAmount                     float64                  `json:"netAmount,omitempty"`
	AmountUSD                     float64                  `json:"amountUSD,omitempty"`
	ServiceFee                    float64                  `json:"serviceFee,omitempty"`
	NetworkFee                    float64                  `json:"networkFee,omitempty"`

	// NetworkRecords               []NetworkRecord               `json:"networkRecords,omitempty"`
	// AuthorizationInfo            AuthorizationInfo             `json:"authorizationInfo"`
	// AmlScreeningResult           AmlScreeningResult            `json:"amlScreeningResult"`
	// ExtraParameters              TransactionExtraParameters    `json:"extraParameters"`
	// SignedMessages               []SignedMessage               `json:"signedMessages,omitempty"`
	// RewardsInfo                  RewardsInfo                   `json:"rewardsInfo"`
}

type AmountInfo struct {
	Amount          string `json:"amount"`
	RequestedAmount string `json:"requestedAmount"`
	NetAmount       string `json:"netAmount"`
	AmountUSD       string `json:"amountUSD"`
}

type FeeInfo struct {
	NetworkFee string `json:"networkFee"`
	ServiceFee string `json:"serviceFee"`
}

type TransferPeerPathResponse struct {
	Type    string `json:"type"`
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	SubType string `json:"subType"`
}

type DestinationsResponse struct {
	Amount                        string                   `json:"amount"`
	Destination                   TransferPeerPathResponse `json:"destination"`
	AmountUSD                     float64                  `json:"amountUSD"`
	DestinationAddress            string                   `json:"destinationAddress"`
	DestinationAddressDescription string                   `json:"destinationAddressDescription,omitempty"`
	CustomerRefID                 string                   `json:"customerRefId,omitempty"`

	// AmlScreeningResult         AmlScreeningResult      `json:"amlScreeningResult"`
}

type SystemMessageInfo struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type BlockInfo struct {
	BlockHeight string `json:"blockHeight"`
	BlockHash   string `json:"blockHash"`
}

type FbCreateTransactionRequest struct {
	Operation          string             `json:"operation"`
	Note               string             `json:"note,omitempty"`
	ExternalTxID       string             `json:"externalTxId,omitempty"`
	AssetID            string             `json:"assetId,omitempty"`
	Source             FbSource           `json:"source"`
	Destination        *FbDestination     `json:"destination,omitempty"`
	Destinations       []any              `json:"destinations,omitempty"`
	CustomerRefID      string             `json:"customerRefId,omitempty"`
	Amount             string             `json:"amountAll,omitempty"`
	TreatAsGrossAmount bool               `json:"treatAsGrossAmount,omitempty"`
	ForceSweep         bool               `json:"forceSweep,omitempty"`
	FeeLevel           string             `json:"feeLevel,omitempty"`
	Fee                string             `json:"fee,omitempty"`
	PriorityFee        string             `json:"priorityFee,omitempty"`
	MaxFee             string             `json:"maxFee,omitempty"`
	GasLimit           string             `json:"gasLimit,omitempty"`
	GasPrice           string             `json:"gasPrice,omitempty"`
	NetworkFee         string             `json:"networkFee,omitempty"`
	ReplaceTxByHash    string             `json:"replaceTxByHash,omitempty"`
	ExtraParameters    *FbExtraParameters `json:"extraParameters,omitempty"`
}

type FbCreateTransactionResponse struct {
	ID             string           `json:"id"`
	Status         FbCTRStatus      `json:"status"`
	SystemMessages FbSystemMessages `json:"systemMessages"`
}

type FbSystemMessages struct {
	Type_   string `json:"type"`
	Message string `json:"message"`
}

type FbExtraParameters struct {
	RawMessageData FbRawMessageData `json:"rawMessageData"`
}

type FbRawMessageData struct {
	Messages  []FbUnsignedRawMessage `json:"messages"`
	Algorithm string                 `json:"algorithm,omitempty"`
}

type FbUnsignedRawMessage struct {
	Content string `json:"content"`
}

type FbSource struct {
	Type     string `json:"type"`
	SubType  string `json:"subType,omitempty"`
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	WalletID string `json:"walletId,omitempty"`
}

type FbDestination struct {
	Type           string            `json:"type"`
	SubType        string            `json:"subType,omitempty"`
	ID             string            `json:"id,omitempty"`
	Name           string            `json:"name,omitempty"`
	WalletID       string            `json:"walletId,omitempty"`
	OneTimeAddress *FbOneTimeAddress `json:"oneTimeAddress,omitempty"`
}

type FbOneTimeAddress struct {
	Address string `json:"address,omitempty"`
	Tag     string `json:"tag,omitempty"`
}

// "SUBMITTED", "PENDING_AML_SCREENING", "PENDING_ENRICHMENT", "PENDING_AUTHORIZATION", “QUEUED”,
// "PENDING_SIGNATURE", "PENDING_3RD_PARTY_MANUAL_APPROVAL", "PENDING_3RD_PARTY", "BROADCASTING", "CONFIRMING", "COMPLETED"
type FbCTRStatus string
