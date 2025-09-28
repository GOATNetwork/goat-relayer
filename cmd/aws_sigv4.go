package main

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/goatnetwork/goat-relayer/internal/config"
)

func BuildBTCConnConfig(cfg config.Config) (*rpcclient.ConnConfig, error) {
	raw := strings.TrimSpace(cfg.BTCRPC)
	if raw == "" {
		return nil, fmt.Errorf("BTC_RPC is empty")
	}
	host := raw

	disableTLS := true
	user := cfg.BTCRPC_USER
	pass := cfg.BTCRPC_PASS

	schemed := strings.HasPrefix(strings.ToLower(host), "http://") || strings.HasPrefix(strings.ToLower(host), "https://")
	if schemed {
		u, err := url.Parse(host)
		if err != nil {
			return nil, fmt.Errorf("invalid BTC_RPC URL %q: %w", host, err)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("invalid BTC_RPC URL %q: missing host", host)
		}
		host = u.Host
		disableTLS = u.Scheme != "https"
		if user == "" && pass == "" && u.User != nil {
			user = u.User.Username()
			pass, _ = u.User.Password()
		}
	} else {
		disableTLS = true
	}

	if host == "" {
		return nil, fmt.Errorf("BTC_RPC host is empty after parsing")
	}

	if cfg.BTCAWSSigV4 {
		disableTLS = false
	}

	return &rpcclient.ConnConfig{
		Host:         host,
		User:         user,
		Pass:         pass,
		HTTPPostMode: true,
		DisableTLS:   disableTLS,
	}, nil
}
