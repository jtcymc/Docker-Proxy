package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testConfigWithSecret() *Config {
	enabled := true
	return &Config{
		Registries: []RegistryConfig{{
			Name:     "ghcr",
			Hosts:    []string{"ghcr.example.com"},
			Upstream: "https://ghcr.io",
			Auth: AuthConfig{
				Type:     AuthToken,
				Username: "example-user",
				Password: "super-secret-token",
			},
			Enabled: &enabled,
		}},
	}
}

func TestHandleAdminConfigAlwaysMasksPasswords(t *testing.T) {
	proxy := NewProxy(testConfigWithSecret())
	request := httptest.NewRequest(http.MethodGet, "/-/config?include_secrets=1", nil)
	recorder := httptest.NewRecorder()

	handleAdminConfig(recorder, request, proxy, "", "admin-token")

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "super-secret-token") {
		t.Fatal("include_secrets=1 must not return a plaintext password")
	}

	var response Config
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got := response.Registries[0].Auth.Password; got != adminPasswordSentinel {
		t.Fatalf("expected masked password %q, got %q", adminPasswordSentinel, got)
	}
	if got := proxy.cfg.Registries[0].Auth.Password; got != "super-secret-token" {
		t.Fatalf("masking the response must not mutate the live config, got %q", got)
	}
}

func TestHandleAdminCredentialsReturnsEncryptedPayload(t *testing.T) {
	const adminToken = "admin-token"
	proxy := NewProxy(testConfigWithSecret())
	request := httptest.NewRequest(http.MethodGet, "/-/credentials", nil)
	recorder := httptest.NewRecorder()

	handleAdminCredentials(recorder, request, proxy, adminToken)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "super-secret-token") {
		t.Fatal("credential sync response must not contain a plaintext password")
	}

	var response credentialSyncResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Algorithm != "AES-256-GCM" {
		t.Fatalf("unexpected algorithm: %s", response.Algorithm)
	}

	sealed, err := base64.StdEncoding.DecodeString(response.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	block, err := aes.NewCipher(credentialSyncKey(adminToken))
	if err != nil {
		t.Fatalf("create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("create gcm: %v", err)
	}
	nonce := sealed[:gcm.NonceSize()]
	ciphertext := sealed[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("decrypt payload: %v", err)
	}
	if !bytes.Contains(plaintext, []byte("super-secret-token")) {
		t.Fatal("decrypted credential payload should contain the configured password")
	}
}

func TestCredentialSyncPayloadCannotBeDecryptedWithAnotherToken(t *testing.T) {
	response, err := encryptCredentialSyncPayload(
		testConfigWithSecret().Registries,
		"admin-token",
	)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}
	sealed, err := base64.StdEncoding.DecodeString(response.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	wrongKey := sha256.Sum256([]byte("wrong-token"))
	block, err := aes.NewCipher(wrongKey[:])
	if err != nil {
		t.Fatalf("create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("create gcm: %v", err)
	}
	_, err = gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
	if err == nil {
		t.Fatal("payload must not decrypt with a different admin token")
	}
}

// TestHostOnly exercises every documented branch of hostOnly. The previous
// `strings.SplitN(h, ":", 2)[0]` returned "[2001" for "[2001:db8::1]:5000"
// and "" for "::1", which is what this table guards against regressing.
func TestHostOnly(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Plain hostname / domain.
		{"example.com", "example.com"},
		{"example.com:5000", "example.com"},
		{"REGISTRY.DOCKER.IO:443", "REGISTRY.DOCKER.IO"}, // lower-casing happens in resolveRegistry
		// Bare IPv4.
		{"127.0.0.1", "127.0.0.1"},
		{"127.0.0.1:8080", "127.0.0.1"},
		// Bracketed IPv6 literal WITH port — the regression case.
		{"[2001:db8::1]:5000", "2001:db8::1"},
		{"[::1]:8080", "::1"},
		// Bracketed IPv6 literal WITHOUT port (some upstream proxies emit this).
		{"[::1]", "::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		// Edge cases.
		{"", ""},
		{":", ""}, // empty host, empty port
	}
	for _, tc := range cases {
		got := hostOnly(tc.in)
		if got != tc.want {
			t.Errorf("hostOnly(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestResolveRegistryIPv6Routes correctly verifies the integration: a request
// bracketed with an IPv6 literal must still match the registry whose Hosts
// entry is the bare IPv6 address.
func TestResolveRegistryIPv6Routes(t *testing.T) {
	enabled := true
	cfg := &Config{
		Default: "v6",
		Registries: []RegistryConfig{{
			Name:     "v6",
			Hosts:    []string{"2001:db8::1", "registry.example.com"},
			Upstream: "https://registry.example.com",
			Auth:     AuthConfig{Type: AuthAnonymous},
			Enabled:  &enabled,
		}},
	}
	p := NewProxy(cfg)
	defer p.stopStatsJanitor()

	// Bracketed form: this is what curl / docker actually emit on `[ipv6]:port` proxies.
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Host = "[2001:db8::1]:5000"
	if reg := p.resolveRegistry(req); reg == nil || reg.Name != "v6" {
		t.Errorf("expected v6 registry for bracketed IPv6 Host, got %+v", reg)
	}
	// X-Forwarded-Host from a reverse proxy that already stripped brackets.
	req2 := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req2.Host = "localhost:5000"
	req2.Header.Set("X-Forwarded-Host", "[2001:db8::1]:5000")
	if reg := p.resolveRegistry(req2); reg == nil || reg.Name != "v6" {
		t.Errorf("expected v6 registry for X-Forwarded-Host (brackets), got %+v", reg)
	}
	// IPv4 sanity-check continues to work.
	req3 := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req3.Host = "registry.example.com:443"
	if reg := p.resolveRegistry(req3); reg == nil || reg.Name != "v6" {
		t.Errorf("expected v6 registry for domain Host, got %+v", reg)
	}
}

// TestResolveRegistryNamespaceQuery covers containerd's dynamic-mirror mode:
// every pull hits one endpoint (the proxy IP as Host) and the ORIGINAL registry
// is carried in the `?ns=` query. Without resolving ns the request previously
// fell through to the default registry and returned a spurious 401.
func TestResolveRegistryNamespaceQuery(t *testing.T) {
	enabled := true
	cfg := &Config{
		Default: "dockerhub",
		Registries: []RegistryConfig{
			{Name: "dockerhub", Hosts: []string{"hub.example"}, Upstream: "https://registry-1.docker.io", Auth: AuthConfig{Type: AuthToken}, Enabled: &enabled},
			{Name: "k8s", Hosts: []string{"k8s.example"}, Upstream: "https://registry.k8s.io", Auth: AuthConfig{Type: AuthToken}, Enabled: &enabled},
		},
	}
	p := NewProxy(cfg)
	defer p.stopStatsJanitor()

	cases := []struct {
		url  string
		want string
	}{
		{"/v2/sig-storage/nfs-subdir-external-provisioner/manifests/v4.0.2?ns=registry.k8s.io", "k8s"},
		{"/v2/library/nginx/manifests/latest?ns=docker.io", "dockerhub"},
		{"/v2/foo/manifests/latest?ns=index.docker.io", "dockerhub"},
		// ns wins over the Host: hub.example is dockerhub, but ns points at k8s.
		{"/v2/pause/manifests/latest?ns=registry.k8s.io", "k8s"},
		// Unknown ns falls back to the default registry.
		{"/v2/foo/manifests/latest?ns=quay.example", "dockerhub"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodHead, tc.url, nil)
		req.Host = "127.0.0.1:50000"
		if tc.want == "k8s" && strings.Contains(tc.url, "pause") {
			req.Host = "hub.example"
		}
		reg := p.resolveRegistry(req)
		if reg == nil || reg.Name != tc.want {
			t.Errorf("ns route for %q: want %q, got %+v", tc.url, tc.want, reg)
		}
	}
}

// TestStatsJanitorEvictsIdleRecords verifies the cleanup loop is wired up:
// entries idle longer than statsIdleTimeout must be removed by cleanupIdleStats.
func TestStatsJanitorEvictsIdleRecords(t *testing.T) {
	p := &Proxy{
		clientStats:         make(map[string]*clientStat),
		statsIdleTimeout:    100 * time.Millisecond,
		statsSweepInterval:  time.Hour, // we drive cleanup manually; the ticker
		// is intentionally huge so it cannot fire during the test.
	}
	// Seed three entries with controlled LastSeen timestamps.
	p.clientStats["fresh-1"] = &clientStat{BytesTotal: 1, Requests: 1, LastSeen: time.Now()}
	p.clientStats["fresh-2"] = &clientStat{BytesTotal: 1, Requests: 1, LastSeen: time.Now()}
	p.clientStats["stale"] = &clientStat{BytesTotal: 1, Requests: 1, LastSeen: time.Now().Add(-time.Hour)}
	// Touch fresh-2 after a tiny wait so it remains newer than the cutoff.
	time.Sleep(20 * time.Millisecond)
	p.clientStats["fresh-2"].LastSeen = time.Now()

	// Drive a single cleanup pass.
	p.cleanupIdleStats()

	if _, ok := p.clientStats["fresh-1"]; !ok {
		t.Error("fresh-1 should have survived cleanup (lastSeen within window)")
	}
	if _, ok := p.clientStats["fresh-2"]; !ok {
		t.Error("fresh-2 should have survived cleanup (recent touch)")
	}
	if _, ok := p.clientStats["stale"]; ok {
		t.Error("stale entry should have been evicted by cleanupIdleStats")
	}
}

// TestApplyStatsConfigClampsBadRatios ensures we never end up in a state where
// the janitor sweep interval is >= idle timeout; otherwise the very first
// sweep deletes everything and the map never recovers.
func TestApplyStatsConfigClampsBadRatios(t *testing.T) {
	p := &Proxy{}
	cfg := &Config{Server: ServerConfig{
		StatsIdleTimeout:     60,   // 60s
		StatsJanitorInterval: 6000, // 100min, way bigger than idle
	}}
	p.applyStatsConfig(cfg)
	if p.statsSweepInterval >= p.statsIdleTimeout {
		t.Fatalf("sweep interval %s must be strictly smaller than idle %s", p.statsSweepInterval, p.statsIdleTimeout)
	}
}
