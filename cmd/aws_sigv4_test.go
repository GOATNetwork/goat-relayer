package main

import (
	"os"
	"testing"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/goatnetwork/goat-relayer/internal/awsutil"
	"github.com/goatnetwork/goat-relayer/internal/config"
	"github.com/stretchr/testify/require"
)

// TestAWSManagedBlockchainRPC exercises a minimal JSON-RPC call against an AWS Managed
// Blockchain Bitcoin node. It is skipped unless BTC_SIGV4_TEST=1 is set in the
// environment and requires standard AWS credential variables.
func TestAWSManagedBlockchainRPC(t *testing.T) {
	if os.Getenv("BTC_SIGV4_TEST") != "1" {
		t.Skip("skipping AWS SigV4 integration test")
	}

	endpoint := os.Getenv("BTC_RPC")
	if endpoint == "" {
		t.Fatal("BTC_RPC must be set to the HTTPS endpoint for the AWS node")
	}

	user := os.Getenv("BTC_RPC_USER")
	pass := os.Getenv("BTC_RPC_PASS")
	if user == "" || pass == "" {
		t.Fatal("BTC_RPC_USER and BTC_RPC_PASS must be provided for basic auth fields")
	}

	region := os.Getenv("BTC_AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	service := os.Getenv("BTC_AWS_SERVICE")
	if service == "" {
		service = "managedblockchain"
	}

	cfg := config.Config{
		BTCRPC:        endpoint,
		BTCRPC_USER:   user,
		BTCRPC_PASS:   pass,
		BTCAWSSigV4:   true,
		BTCAWSRegion:  region,
		BTCAWSService: service,
	}

	connCfg, err := BuildBTCConnConfig(cfg)
	require.NoError(t, err)

	client, err := rpcclient.New(connCfg, nil)
	require.NoError(t, err)
	defer client.Shutdown()

	require.NoError(t, awsutil.AttachSigV4Signer(client, region, service, user, pass, os.Getenv("AWS_SESSION_TOKEN")))
	require.NoError(t, awsutil.PrimeBitcoindBackendVersion(client))

	info, err := client.GetBlockChainInfo()
	t.Logf("blockchain info: %+v", info)
	require.NoError(t, err)
	if info.Chain == "" {
		t.Fatal("expected blockchain info to include chain name")
	}
}
