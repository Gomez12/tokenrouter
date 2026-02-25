package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lkarlslund/tokenrouter/pkg/config"
)

func TestProxyQuotaBlocksAndEmitsHeadersAndJSON(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer upstream.Close()

	cfg := config.NewDefaultServerConfig()
	cfg.AllowLocalhostNoAuth = false
	cfg.IncomingTokens = []config.IncomingAPIToken{
		{
			ID:   "tok-root",
			Name: "Root",
			Key:  "root-key",
			Role: config.TokenRoleInferrer,
			Quota: &config.TokenQuota{
				Requests: &config.TokenQuotaBudget{Limit: 1},
			},
		},
	}
	cfg.Providers = []config.ProviderConfig{
		{Name: "test-provider", BaseURL: upstream.URL + "/v1", APIKey: "provider-key", Enabled: true, TimeoutSeconds: 10},
	}
	s, err := NewServer(filepath.Join(t.TempDir(), "torod.toml"), cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req1 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test-provider/test-model","messages":[{"role":"user","content":"hi"}]}`))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Authorization", "Bearer root-key")
	w1 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d body=%s", w1.Code, w1.Body.String())
	}
	if got := strings.TrimSpace(w1.Header().Get("x-ratelimit-limit")); got != "1" {
		t.Fatalf("expected x-ratelimit-limit=1, got %q", got)
	}
	if got := strings.TrimSpace(w1.Header().Get("x-ratelimit-remaining")); got != "0" {
		t.Fatalf("expected x-ratelimit-remaining=0, got %q", got)
	}
	if got := strings.TrimSpace(w1.Header().Get("ratelimit-limit")); got != "1" {
		t.Fatalf("expected ratelimit-limit=1, got %q", got)
	}
	var firstBody map[string]any
	if err := json.Unmarshal(w1.Body.Bytes(), &firstBody); err != nil {
		t.Fatalf("decode first body: %v", err)
	}
	quota, ok := firstBody["quota"].(map[string]any)
	if !ok {
		t.Fatalf("expected quota object in first response, got %v", firstBody["quota"])
	}
	reqQuota, ok := quota["requests"].(map[string]any)
	if !ok {
		t.Fatalf("expected requests quota object, got %v", quota["requests"])
	}
	if int(reqQuota["remaining"].(float64)) != 0 {
		t.Fatalf("expected remaining 0, got %v", reqQuota["remaining"])
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test-provider/test-model","messages":[{"role":"user","content":"again"}]}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer root-key")
	w2 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request 429, got %d body=%s", w2.Code, w2.Body.String())
	}
	var secondBody map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &secondBody); err != nil {
		t.Fatalf("decode second body: %v", err)
	}
	errObj, ok := secondBody["error"].(map[string]any)
	if !ok || strings.TrimSpace(asString(errObj["code"])) != "insufficient_quota" {
		t.Fatalf("expected insufficient_quota error, got %v", secondBody["error"])
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("expected one upstream call before quota block, got %d", upstreamCalls.Load())
	}
}

func TestProxyQuotaSubordinateUsesOwnerQuota(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer upstream.Close()

	cfg := config.NewDefaultServerConfig()
	cfg.AllowLocalhostNoAuth = false
	cfg.IncomingTokens = []config.IncomingAPIToken{
		{
			ID:   "owner",
			Name: "Owner",
			Key:  "owner-key",
			Role: config.TokenRoleInferrer,
			Quota: &config.TokenQuota{
				Requests: &config.TokenQuotaBudget{Limit: 1},
			},
		},
		{
			ID:       "child",
			Name:     "Child",
			Key:      "child-key",
			Role:     config.TokenRoleInferrer,
			ParentID: "owner",
		},
	}
	cfg.Providers = []config.ProviderConfig{
		{Name: "test-provider", BaseURL: upstream.URL + "/v1", APIKey: "provider-key", Enabled: true, TimeoutSeconds: 10},
	}
	s, err := NewServer(filepath.Join(t.TempDir(), "torod.toml"), cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req1 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test-provider/test-model","messages":[{"role":"user","content":"hi"}]}`))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Authorization", "Bearer child-key")
	w1 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected first subordinate request 200, got %d body=%s", w1.Code, w1.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test-provider/test-model","messages":[{"role":"user","content":"again"}]}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer child-key")
	w2 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second subordinate request 429, got %d body=%s", w2.Code, w2.Body.String())
	}
}

func TestProxyNoQuotaSkipsQuotaMetadata(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer upstream.Close()

	cfg := config.NewDefaultServerConfig()
	cfg.AllowLocalhostNoAuth = false
	cfg.IncomingTokens = []config.IncomingAPIToken{
		{ID: "tok", Name: "NoQuota", Key: "no-quota-key", Role: config.TokenRoleInferrer},
	}
	cfg.Providers = []config.ProviderConfig{
		{Name: "test-provider", BaseURL: upstream.URL + "/v1", APIKey: "provider-key", Enabled: true, TimeoutSeconds: 10},
	}
	s, err := NewServer(filepath.Join(t.TempDir(), "torod.toml"), cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test-provider/test-model","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer no-quota-key")
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if got := strings.TrimSpace(w.Header().Get("x-ratelimit-limit")); got != "" {
		t.Fatalf("expected no quota headers, got x-ratelimit-limit=%q", got)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if _, ok := body["quota"]; ok {
		t.Fatalf("expected no quota field in body, got %v", body["quota"])
	}
}
