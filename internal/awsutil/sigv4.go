package awsutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	awsv4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/btcsuite/btcd/rpcclient"
)

// AttachSigV4Signer wraps the btc RPC client's HTTP transport with a SigV4 signer.
func AttachSigV4Signer(client *rpcclient.Client, region, service, accessKey, secretKey, sessionToken string) error {
	if client == nil {
		return fmt.Errorf("rpc client is nil")
	}
	if region == "" {
		return fmt.Errorf("AWS region is empty")
	}
	if service == "" {
		return fmt.Errorf("AWS service is empty")
	}

	creds, err := loadStaticCredentials(accessKey, secretKey, sessionToken)
	if err != nil {
		return err
	}

	httpClient, err := extractHTTPClient(client)
	if err != nil {
		return err
	}
	baseTransport := httpClient.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}

	signer := awsv4.NewSigner(creds)
	httpClient.Transport = &sigV4Transport{
		base:    baseTransport,
		signer:  signer,
		region:  region,
		service: service,
	}

	return nil
}

func loadStaticCredentials(accessKey, secretKey, sessionToken string) (*credentials.Credentials, error) {
	// 1. Try static credentials if explicitly provided
	if accessKey != "" && secretKey != "" {
		return credentials.NewStaticCredentials(accessKey, secretKey, sessionToken), nil
	}

	// 2. Try environment credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
	if creds := credentials.NewEnvCredentials(); creds != nil {
		if value, err := creds.Get(); err == nil && value.AccessKeyID != "" && value.SecretAccessKey != "" {
			return creds, nil
		}
	}

	// 3. Try shared credentials file (~/.aws/credentials)
	profile := os.Getenv("AWS_PROFILE")
	if profile == "" {
		profile = "default"
	}
	if creds := credentials.NewSharedCredentials("", profile); creds != nil {
		if value, err := creds.Get(); err == nil && value.AccessKeyID != "" && value.SecretAccessKey != "" {
			return creds, nil
		}
	}

	// 4. Try EC2 instance role credentials (IAM role attached to EC2 instance)
	sess, err := session.NewSession()
	if err == nil {
		metadataClient := ec2metadata.New(sess)
		creds := credentials.NewCredentials(&ec2rolecreds.EC2RoleProvider{
			Client: metadataClient,
		})
		if value, err := creds.Get(); err == nil && value.AccessKeyID != "" && value.SecretAccessKey != "" {
			return creds, nil
		}
	}

	return nil, fmt.Errorf("unable to find AWS credentials via environment variables, shared config, or EC2 instance role")
}

// PrimeBitcoindBackendVersion discovers the remote bitcoind version via
// getnetworkinfo and seeds the client's backendVersion cache so subsequent RPCs
// do not attempt unsupported detection calls (for example, getinfo).
func PrimeBitcoindBackendVersion(client *rpcclient.Client) error {
	if client == nil {
		return fmt.Errorf("rpc client is nil")
	}

	resp, err := client.RawRequest("getnetworkinfo", nil)
	if err != nil {
		if strings.Contains(err.Error(), "status code: 403") {
			return setBackendVersion(client, rpcclient.BitcoindPost25)
		}
		return fmt.Errorf("getnetworkinfo request failed: %w", err)
	}

	var networkInfo struct {
		SubVersion string  `json:"subversion"`
		Version    float64 `json:"version"`
	}
	if err := json.Unmarshal(resp, &networkInfo); err != nil {
		return fmt.Errorf("failed to decode getnetworkinfo response: %w", err)
	}

	subVersion := networkInfo.SubVersion
	if subVersion == "" {
		if networkInfo.Version == 0 {
			return fmt.Errorf("getnetworkinfo response missing subversion and version")
		}
		subVersion = deriveSatoshiSubVersion(networkInfo.Version)
	}

	if subVersion == "" {
		return fmt.Errorf("getnetworkinfo response missing subversion")
	}

	version := classifyBitcoindVersion(subVersion)
	return setBackendVersion(client, version)
}

func deriveSatoshiSubVersion(version float64) string {
	if version <= 0 {
		return ""
	}

	intVersion := int(version)
	major := intVersion / 1000000
	minor := (intVersion / 10000) % 100
	patch := (intVersion / 100) % 100

	return fmt.Sprintf("/Satoshi:%d.%d.%d/", major, minor, patch)
}

func classifyBitcoindVersion(subVersion string) rpcclient.BitcoindVersion {
	trimmed := strings.TrimPrefix(strings.TrimSuffix(subVersion, "/"), "/Satoshi:")
	maj, min, patch := parseSemver(trimmed)

	switch {
	case versionLessThan(maj, min, patch, 0, 19, 0):
		return rpcclient.BitcoindPre19
	case versionLessThan(maj, min, patch, 22, 0, 0):
		return rpcclient.BitcoindPre22
	case versionLessThan(maj, min, patch, 24, 0, 0):
		return rpcclient.BitcoindPre24
	case versionLessThan(maj, min, patch, 25, 0, 0):
		return rpcclient.BitcoindPre25
	default:
		return rpcclient.BitcoindPost25
	}
}

func parseSemver(v string) (int, int, int) {
	parts := strings.Split(v, ".")
	values := [3]int{}
	for i := 0; i < len(values) && i < len(parts); i++ {
		if intVal, err := strconv.Atoi(parts[i]); err == nil {
			values[i] = intVal
		}
	}
	return values[0], values[1], values[2]
}

func versionLessThan(majorA, minorA, patchA, majorB, minorB, patchB int) bool {
	if majorA != majorB {
		return majorA < majorB
	}
	if minorA != minorB {
		return minorA < minorB
	}
	return patchA < patchB
}

func setBackendVersion(client *rpcclient.Client, version rpcclient.BackendVersion) error {
	if client == nil {
		return fmt.Errorf("rpc client is nil")
	}

	val := reflect.ValueOf(client)
	if val.Kind() != reflect.Ptr || val.IsNil() {
		return fmt.Errorf("rpc client is invalid")
	}
	clientVal := val.Elem()

	muField := clientVal.FieldByName("backendVersionMu")
	if !muField.IsValid() {
		return fmt.Errorf("rpc client missing backendVersionMu field")
	}
	muPtr := (*sync.Mutex)(unsafe.Pointer(muField.UnsafeAddr()))
	muPtr.Lock()
	defer muPtr.Unlock()

	versionField := clientVal.FieldByName("backendVersion")
	if !versionField.IsValid() {
		return fmt.Errorf("rpc client missing backendVersion field")
	}
	reflect.NewAt(versionField.Type(), unsafe.Pointer(versionField.UnsafeAddr())).Elem().Set(reflect.ValueOf(version))

	return nil
}

func extractHTTPClient(client *rpcclient.Client) (*http.Client, error) {
	rv := reflect.ValueOf(client)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return nil, fmt.Errorf("rpc client is invalid")
	}
	elem := rv.Elem()
	field := elem.FieldByName("httpClient")
	if !field.IsValid() {
		return nil, fmt.Errorf("rpc client does not expose httpClient field")
	}
	if field.IsNil() {
		return nil, fmt.Errorf("rpc client httpClient is nil")
	}

	ptr := unsafe.Pointer(field.UnsafeAddr())
	httpClient := *(**http.Client)(ptr)
	if httpClient == nil {
		return nil, fmt.Errorf("rpc client httpClient pointer is nil")
	}

	return httpClient, nil
}

type sigV4Transport struct {
	base    http.RoundTripper
	signer  *awsv4.Signer
	region  string
	service string
}

func (t *sigV4Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	bodyReader, err := cloneRequestBody(req)
	if err != nil {
		return nil, err
	}

	req.Header.Del("Authorization")
	req.Header.Del("X-Amz-Date")
	req.Header.Del("X-Amz-Content-Sha256")
	req.Header.Del("X-Amz-Security-Token")

	if _, err := t.signer.Sign(req, bodyReader, t.service, t.region, time.Now()); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	if _, err := bodyReader.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to reset request body reader: %w", err)
	}

	return t.base.RoundTrip(req)
}

func cloneRequestBody(req *http.Request) (io.ReadSeeker, error) {
	if req.Body == nil {
		return bytes.NewReader(nil), nil
	}

	if req.GetBody != nil {
		rc, err := req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("failed to clone request body: %w", err)
		}
		defer rc.Close()
		buf, err := io.ReadAll(rc)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		return bytes.NewReader(buf), nil
	}

	buf, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	if err := req.Body.Close(); err != nil {
		return nil, fmt.Errorf("failed to close original request body: %w", err)
	}

	reader := bytes.NewReader(buf)
	req.Body = io.NopCloser(bytes.NewReader(buf))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf)), nil
	}
	req.ContentLength = int64(len(buf))

	return reader, nil
}
