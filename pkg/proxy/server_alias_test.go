package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/tokenrouter/pkg/config"
)

func TestProxyHandlerRewritesAliasModelAndPreservesIncomingStatsModel(t *testing.T) {
	var upstreamModel string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode upstream payload: %v", err)
		}
		upstreamModel = strings.TrimSpace(anyToString(payload["model"]))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3},"choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer upstream.Close()

	cfg := config.NewDefaultServerConfig()
	cfg.Providers = []config.ProviderConfig{
		{Name: "test-provider", BaseURL: upstream.URL + "/v1", Enabled: true, TimeoutSeconds: 5},
	}
	cfg.ActiveModelProfile = "local"
	cfg.ModelAliases = []config.ModelAliasConfig{
		{Name: "chat", Targets: []config.ModelAliasTarget{{Profile: "local", Provider: "test-provider", Model: "test-model"}}},
	}
	store := config.NewServerConfigStore(filepath.Join(t.TempDir(), "server.toml"), cfg)
	resolver := NewProviderResolver(store)
	s := &Server{
		store:                 store,
		resolver:              resolver,
		stats:                 NewStatsStore(100),
		providerHealthChecker: NewProviderHealthChecker(resolver, providerHealthCheckInterval),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"chat","messages":[{"role":"user","content":"hi"}]}`))
	w := httptest.NewRecorder()
	s.proxyHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}
	if upstreamModel != "test-model" {
		t.Fatalf("expected upstream model test-model, got %q", upstreamModel)
	}
	summary := s.stats.Summary(time.Hour)
	if got := summary.RequestsPerModel["chat"]; got != 1 {
		t.Fatalf("expected alias model stats entry for chat, got %d", got)
	}
}

func TestProxyHandlerUsesUpdatedActiveProfileWithoutRestart(t *testing.T) {
	var localRequests int
	localUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		localRequests++
		_, _ = w.Write([]byte(`{"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2},"choices":[{"message":{"role":"assistant","content":"local"}}]}`))
	}))
	defer localUpstream.Close()

	var runpodRequests int
	runpodUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runpodRequests++
		_, _ = w.Write([]byte(`{"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2},"choices":[{"message":{"role":"assistant","content":"runpod"}}]}`))
	}))
	defer runpodUpstream.Close()

	cfg := config.NewDefaultServerConfig()
	cfg.Providers = []config.ProviderConfig{
		{Name: "local-provider", BaseURL: localUpstream.URL, Enabled: true, TimeoutSeconds: 5},
		{Name: "runpod-provider", BaseURL: runpodUpstream.URL, Enabled: true, TimeoutSeconds: 5},
	}
	cfg.ActiveModelProfile = "local"
	cfg.ModelAliases = []config.ModelAliasConfig{
		{
			Name: "chat",
			Targets: []config.ModelAliasTarget{
				{Profile: "local", Provider: "local-provider", Model: "local-model"},
				{Profile: "runpod", Provider: "runpod-provider", Model: "runpod-model"},
			},
		},
	}
	store := config.NewServerConfigStore(filepath.Join(t.TempDir(), "server.toml"), cfg)
	resolver := NewProviderResolver(store)
	s := &Server{
		store:                 store,
		resolver:              resolver,
		stats:                 NewStatsStore(100),
		providerHealthChecker: NewProviderHealthChecker(resolver, providerHealthCheckInterval),
	}

	req1 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"chat","messages":[{"role":"user","content":"hi"}]}`))
	w1 := httptest.NewRecorder()
	s.proxyHandler(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected first request status 200, got %d body=%s", w1.Code, w1.Body.String())
	}
	if localRequests != 1 || runpodRequests != 0 {
		t.Fatalf("expected local=1 runpod=0 after first request, got local=%d runpod=%d", localRequests, runpodRequests)
	}

	if err := store.Update(func(c *config.ServerConfig) error {
		c.ActiveModelProfile = "runpod"
		return nil
	}); err != nil {
		t.Fatalf("update active profile: %v", err)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"chat","messages":[{"role":"user","content":"again"}]}`))
	w2 := httptest.NewRecorder()
	s.proxyHandler(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected second request status 200, got %d body=%s", w2.Code, w2.Body.String())
	}
	if localRequests != 1 || runpodRequests != 1 {
		t.Fatalf("expected local=1 runpod=1 after switch, got local=%d runpod=%d", localRequests, runpodRequests)
	}
}

func TestHandleModelsIncludesResolvableAliasesOnly(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"test-model"}]}`))
	}))
	defer upstream.Close()

	cfg := config.NewDefaultServerConfig()
	cfg.Providers = []config.ProviderConfig{
		{Name: "test-provider", BaseURL: upstream.URL, Enabled: true, TimeoutSeconds: 5},
	}
	cfg.ActiveModelProfile = "local"
	cfg.ModelAliases = []config.ModelAliasConfig{
		{Name: "chat", Targets: []config.ModelAliasTarget{{Profile: "local", Provider: "test-provider", Model: "test-model"}}},
		{Name: "broken", Targets: []config.ModelAliasTarget{{Profile: "local", Provider: "missing-provider", Model: "missing-model"}}},
	}
	store := config.NewServerConfigStore(filepath.Join(t.TempDir(), "server.toml"), cfg)
	s := &Server{
		store:    store,
		resolver: NewProviderResolver(store),
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	w := httptest.NewRecorder()
	s.handleModels(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Data []ModelCard `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode models body: %v", err)
	}
	foundAlias := false
	foundBroken := false
	for _, card := range body.Data {
		if card.ID == "chat" {
			foundAlias = true
			if !card.Alias || card.ResolvedProvider != "test-provider" || card.ResolvedModel != "test-model" {
				t.Fatalf("unexpected alias card: %+v", card)
			}
		}
		if card.ID == "broken" {
			foundBroken = true
		}
	}
	if !foundAlias {
		t.Fatal("expected chat alias in model list")
	}
	if foundBroken {
		t.Fatal("did not expect unresolved alias in model list")
	}
}
