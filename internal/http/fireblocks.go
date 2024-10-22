package http

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/goatnetwork/goat-relayer/internal/db"
	"github.com/goatnetwork/goat-relayer/internal/types"
	"github.com/golang-jwt/jwt/v5"

	log "github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
)

const (
	webhookPkProduction = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0+6wd9OJQpK60ZI7qnZG
jjQ0wNFUHfRv85Tdyek8+ahlg1Ph8uhwl4N6DZw5LwLXhNjzAbQ8LGPxt36RUZl5
YlxTru0jZNKx5lslR+H4i936A4pKBjgiMmSkVwXD9HcfKHTp70GQ812+J0Fvti/v
4nrrUpc011Wo4F6omt1QcYsi4GTI5OsEbeKQ24BtUd6Z1Nm/EP7PfPxeb4CP8KOH
clM8K7OwBUfWrip8Ptljjz9BNOZUF94iyjJ/BIzGJjyCntho64ehpUYP8UJykLVd
CGcu7sVYWnknf1ZGLuqqZQt4qt7cUUhFGielssZP9N9x7wzaAIFcT3yQ+ELDu1SZ
dE4lZsf2uMyfj58V8GDOLLE233+LRsRbJ083x+e2mW5BdAGtGgQBusFfnmv5Bxqd
HgS55hsna5725/44tvxll261TgQvjGrTxwe7e5Ia3d2Syc+e89mXQaI/+cZnylNP
SwCCvx8mOM847T0XkVRX3ZrwXtHIA25uKsPJzUtksDnAowB91j7RJkjXxJcz3Vh1
4k182UFOTPRW9jzdWNSyWQGl/vpe9oQ4c2Ly15+/toBo4YXJeDdDnZ5c/O+KKadc
IMPBpnPrH/0O97uMPuED+nI6ISGOTMLZo35xJ96gPBwyG5s2QxIkKPXIrhgcgUnk
tSM7QYNhlftT4/yVvYnk0YcCAwEAAQ==
-----END PUBLIC KEY-----`
	webhookPkSandbox = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw+fZuC+0vDYTf8fYnCN6
71iHg98lPHBmafmqZqb+TUexn9sH6qNIBZ5SgYFxFK6dYXIuJ5uoORzihREvZVZP
8DphdeKOMUrMr6b+Cchb2qS8qz8WS7xtyLU9GnBn6M5mWfjkjQr1jbilH15Zvcpz
ECC8aPUAy2EbHpnr10if2IHkIAWLYD+0khpCjpWtsfuX+LxqzlqQVW9xc6z7tshK
eCSEa6Oh8+ia7Zlu0b+2xmy2Arb6xGl+s+Rnof4lsq9tZS6f03huc+XVTmd6H2We
WxFMfGyDCX2akEg2aAvx7231/6S0vBFGiX0C+3GbXlieHDplLGoODHUt5hxbPJnK
IwIDAQAB
-----END PUBLIC KEY-----`
)

// handleFireblocksWebhook process webhook callback of Fireblocks, should validate request data first
func (s *HTTPServer) handleFireblocksWebhook(c *gin.Context) {
	bodyBytes, err := s.verifyWebhookSig(c)
	if err != nil {
		log.Errorf("Fireblocks webhook sig verify error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Sig error"})
		return
	}

	var req FireblocksWebhookRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		log.Errorf("Fireblocks webhook json bind error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	log.Infof("Fireblocks webhook received, Type: %s, TenantId: %s, Timestamp: %d, Data: %v",
		req.Type, req.TenantId, req.Timestamp, req.Data)

	// TODO: record
	if req.Type == "TRANSACTION_CREATED" {
		var trans TransactionDetails
		if err := json.Unmarshal(req.Data, &trans); err == nil {
			log.Infof("Fireblocks webhook transaction created detect, txId %s, txHash %s, status %s", trans.ExternalTxID, trans.TxHash, trans.Status)
		} else {
			log.Error("Fireblocks webhook failed to convert data to TransactionDetails")
		}
	}
	if req.Type == "TRANSACTION_STATUS_UPDATED" {
		var trans TransactionDetails
		if err := json.Unmarshal(req.Data, &trans); err == nil {
			log.Infof("Transaction status updated detect, txId %s, txHash %s, status %s, subStatus %s, assetType %s, amount %s", trans.ExternalTxID, trans.TxHash, trans.Status, trans.SubStatus, trans.AssetType, trans.AmountInfo.Amount)
			if trans.Operation == "TRANSFER" && trans.Status == "COMPLETED" && trans.SubStatus == "CONFIRMED" {
				// TODO: withdraw filter (sourceAddress, destinationAddress, assetType)
				log.Infof("Fireblocks webhook transaction confirmed, txId %s, txHash %s, sourceAddress %s, destinationAddress %s, assetType %s, amount %s", trans.ExternalTxID, trans.TxHash, trans.SourceAddress, trans.DestinationAddress, trans.AssetType, trans.AmountInfo.Amount)
			}
		} else {
			log.Error("Fireblocks webhook failed to convert data to TransactionDetails")
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// handleFireblocksCosignerTxSign process cosigner tx sign callback of Fireblocks, it will check tx and sign
func (s *HTTPServer) handleFireblocksCosignerTxSign(c *gin.Context) {
	if config.AppConfig.FireblocksPrivKey == "" || config.AppConfig.FireblocksPubKey == "" {
		log.Error("Cosigner callback empty RSA key")
		c.String(http.StatusInternalServerError, "Private key and public key not exist")
		return
	}

	rsaPubKey, err := types.ParseRSAPublicKeyFromPEM(config.AppConfig.FireblocksPubKey)
	if err != nil {
		log.Errorf("Cosigner error parsing RSA public key: %v", err)
		c.String(http.StatusInternalServerError, "Public key parsing error")
		return
	}

	rsaPrivKey, err := types.ParseRSAPrivateKeyFromPEM(config.AppConfig.FireblocksPrivKey)
	if err != nil {
		log.Errorf("Cosigner error parsing RSA private key: %v", err)
		c.String(http.StatusInternalServerError, "Private key parsing error")
		return
	}

	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Errorf("Cosigner error read body: %v", err)
		c.Status(http.StatusInternalServerError)
		return
	}
	rawBody := string(bodyBytes)

	// Parse and verify JWT
	tx, err := jwt.Parse(rawBody, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrInvalidKey
		}
		return rsaPubKey, nil
	})
	if err != nil {
		log.Error("Cosigner callback JWT parsing failed")
		c.Status(http.StatusUnauthorized)
		return
	}

	if !tx.Valid {
		log.Error("Cosigner callback JWT tx not valid")
		c.Status(http.StatusUnauthorized)
		return
	}

	// Extract requestId from the JWT claims
	claims, ok := tx.Claims.(jwt.MapClaims)
	if !ok {
		log.Error("Cosigner callback JWT claims parsing failed")
		c.Status(http.StatusUnauthorized)
		return
	}

	requestId := claims["requestId"].(string)
	txId := claims["txId"].(string)
	note := claims["note"].(string)
	log.Infof("Cosigner callback JWT claim received, requestId %s, txId %s, note %s", requestId, txId, note)
	// 使用trim去除note的前缀 "WITHDRAW"
	txHash := strings.Split(note, ":")[1]

	// Sign the response APPROVE|REJECT|RETRY
	action := "APPROVE"
	rejectionReason := ""

	// check by more fields
	sendOrder, err := s.state.GetSendOrderByTxIdOrExternalId(txHash)
	if err != nil {
		log.Errorf("Cosigner callback get send order error: %v", err)
		action = "RETRY"
		rejectionReason = "read db error"
	} else if sendOrder == nil {
		log.Errorf("Cosigner callback send order not found: txId %s", txId)
		action = "REJECT"
		rejectionReason = "send order not found"
	} else if sendOrder.Status != db.ORDER_STATUS_INIT && sendOrder.Status != db.ORDER_STATUS_PENDING {
		log.Errorf("Cosigner callback send order status not expected, current status: %s", sendOrder.Status)
		action = "REJECT"
		rejectionReason = "send order status not expected, current status: " + sendOrder.Status
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"action":          action,
		"requestId":       requestId,
		"rejectionReason": rejectionReason,
	})
	signedRes, err := token.SignedString(rsaPrivKey)
	if err != nil {
		log.Errorf("Cosigner callback JWT signing failed: %v, rejectionReason: %s", err, rejectionReason)
		c.Status(http.StatusInternalServerError)
		return
	}

	log.Infof("Cosigner callback JWT signed, signedRes: %s, requestId: %s, txId: %s, note: %s", signedRes, requestId, txId, note)
	c.String(http.StatusOK, signedRes)
}

// verifyWebhookSig verify sig from webhook request
func (s *HTTPServer) verifyWebhookSig(c *gin.Context) ([]byte, error) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, err
	}
	// Get sig
	signature := c.GetHeader("fireblocks-signature")
	if signature == "" {
		return nil, errors.New("signature missing")
	}

	// Decode from base64
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, errors.New("invalid signature encoding")
	}

	// Extract pk
	rsaPub, err := types.ParseRSAPublicKeyFromPEM(webhookPkProduction)
	if err != nil {
		return nil, err
	}

	// Create SHA-512 hash
	hash := sha512.New()
	hash.Write(body)
	hashed := hash.Sum(nil)

	// Verify sig
	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA512, hashed, sig)
	if err != nil {
		log.Errorf("Fireblocks webhook verification failed: %v", err)
		return nil, errors.New("invalid signature")
	}
	return body, nil
}
