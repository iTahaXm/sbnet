package common

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ─────────────────────────────────────────────
// Verified consensus fetch
// ─────────────────────────────────────────────
//
// Every component that consumes a directory consensus (client, broker, bridge)
// MUST verify the directory's ed25519 signature before trusting the relay list.
// Skipping verification lets a MITM inject malicious relays. This shared helper
// guarantees the check is applied consistently.

// BuildHTTPClient returns an HTTP client. If caFile is non-empty, the directory
// TLS connection is verified against that CA only; otherwise the system pool
// is used.
func BuildHTTPClient(caFile string) (*http.Client, error) {
	tlsCfg := &tls.Config{}
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read directory CA %s: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid certs in %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

// FetchVerifiedConsensus fetches the directory pubkey and consensus, verifies
// the ed25519 signature over RelaysJSON+BrokersJSON, and checks the timestamp
// freshness window. It returns an error rather than an unverified document.
func FetchVerifiedConsensus(dirURL, caFile string) (*SignedConsensus, error) {
	httpClient, err := BuildHTTPClient(caFile)
	if err != nil {
		return nil, err
	}

	pkResp, err := httpClient.Get(dirURL + "/pubkey")
	if err != nil {
		return nil, fmt.Errorf("fetch pubkey: %w", err)
	}
	pkBytes, _ := io.ReadAll(pkResp.Body)
	pkResp.Body.Close()

	pubkeyBytes, err := hex.DecodeString(strings.TrimSpace(string(pkBytes)))
	if err != nil || len(pubkeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("decode directory pubkey: %w", err)
	}
	dirPubkey := ed25519.PublicKey(pubkeyBytes)

	resp, err := httpClient.Get(dirURL + "/consensus")
	if err != nil {
		return nil, fmt.Errorf("fetch consensus: %w", err)
	}
	defer resp.Body.Close()

	var consensus SignedConsensus
	if err := json.NewDecoder(resp.Body).Decode(&consensus); err != nil {
		return nil, fmt.Errorf("decode consensus: %w", err)
	}

	sigBytes, err := hex.DecodeString(consensus.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode consensus signature: %w", err)
	}
	sigPayload := append([]byte(consensus.RelaysJSON), []byte(consensus.BrokersJSON)...)
	if !ed25519.Verify(dirPubkey, sigPayload, sigBytes) {
		return nil, fmt.Errorf("consensus signature invalid — possible MITM attack")
	}
	age := time.Now().Unix() - consensus.Timestamp
	if age > 600 || age < -60 {
		return nil, fmt.Errorf("consensus timestamp out of range (%ds)", age)
	}
	return &consensus, nil
}
