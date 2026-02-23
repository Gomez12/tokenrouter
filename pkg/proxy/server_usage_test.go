package proxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/openai-personal-proxy/pkg/config"
)

func TestRecordUsageCountsRequestWithoutUsagePayload(t *testing.T) {
	s := &Server{stats: NewStatsStore(100)}
	s.recordUsage("openai", "openai/gpt-4.1", "gpt-4.1", 200, 120*time.Millisecond, []byte(`{"id":"resp_123","object":"response"}`))

	summary := s.stats.Summary(time.Hour)
	if summary.Requests != 1 {
		t.Fatalf("expected 1 request, got %d", summary.Requests)
	}
	if summary.TotalTokens != 0 {
		t.Fatalf("expected 0 total tokens, got %d", summary.TotalTokens)
	}
	if got := summary.RequestsPerProvider["openai"]; got != 1 {
		t.Fatalf("expected provider request count 1, got %d", got)
	}
	if got := summary.RequestsPerModel["openai/gpt-4.1"]; got != 1 {
		t.Fatalf("expected model request count 1, got %d", got)
	}
}

func TestRecordUsageParsesResponsesUsageSchema(t *testing.T) {
	s := &Server{stats: NewStatsStore(100)}
	body := []byte(`{"usage":{"input_tokens":11,"output_tokens":7,"total_tokens":18}}`)
	s.recordUsage("openai", "openai/gpt-4.1", "gpt-4.1", 200, 250*time.Millisecond, body)

	summary := s.stats.Summary(time.Hour)
	if summary.Requests != 1 {
		t.Fatalf("expected 1 request, got %d", summary.Requests)
	}
	if summary.PromptTokens != 11 {
		t.Fatalf("expected 11 prompt tokens, got %d", summary.PromptTokens)
	}
	if summary.CompletionTokens != 7 {
		t.Fatalf("expected 7 completion tokens, got %d", summary.CompletionTokens)
	}
	if summary.TotalTokens != 18 {
		t.Fatalf("expected 18 total tokens, got %d", summary.TotalTokens)
	}
}

func TestProxyHandlerStreamingRecordsUsageRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\n\n"))
		_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":4,\"output_tokens\":3,\"total_tokens\":7}}}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()

	cfg := config.NewDefaultServerConfig()
	cfg.Providers = []config.ProviderConfig{
		{
			Name:           "test-provider",
			BaseURL:        upstream.URL + "/v1",
			APIKey:         "test-key",
			Enabled:        true,
			TimeoutSeconds: 10,
		},
	}
	store := config.NewServerConfigStore(filepath.Join(t.TempDir(), "config.toml"), cfg)
	resolver := NewProviderResolver(store)

	s := &Server{
		store:                 store,
		resolver:              resolver,
		stats:                 NewStatsStore(100),
		providerHealthChecker: NewProviderHealthChecker(resolver, providerHealthCheckInterval),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"test-provider/test-model","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.proxyHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	summary := s.stats.Summary(time.Hour)
	if summary.Requests != 1 {
		t.Fatalf("expected 1 request, got %d", summary.Requests)
	}
	if summary.TotalTokens != 7 {
		t.Fatalf("expected 7 total tokens, got %d", summary.TotalTokens)
	}
	if summary.PromptTokens != 4 {
		t.Fatalf("expected 4 prompt tokens, got %d", summary.PromptTokens)
	}
	if summary.CompletionTokens != 3 {
		t.Fatalf("expected 3 completion tokens, got %d", summary.CompletionTokens)
	}
}

func TestParseUsageTokensFindsNestedUsage(t *testing.T) {
	body := []byte(`{"type":"response.completed","response":{"usage":{"input_tokens":2,"output_tokens":5,"total_tokens":7}}}`)
	p, c, total := parseUsageTokens(body)
	if p != 2 || c != 5 || total != 7 {
		t.Fatalf("unexpected usage parse result p=%d c=%d t=%d", p, c, total)
	}
}

func TestComputePromptAndGenerationTPSUsesPhaseTimings(t *testing.T) {
	promptTPS, genTPS := computePromptAndGenerationTPS(200, 100, 2*time.Second, 12*time.Second)
	if promptTPS != 100 {
		t.Fatalf("expected prompt tps 100, got %f", promptTPS)
	}
	if genTPS != 10 {
		t.Fatalf("expected generation tps 10, got %f", genTPS)
	}
}

func TestProxyHandlerFallbackEstimatesTokensWithoutUsageNonStreaming(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"resp_1","output_text":"short reply"}`))
	}))
	defer upstream.Close()

	cfg := config.NewDefaultServerConfig()
	cfg.Providers = []config.ProviderConfig{
		{
			Name:           "test-provider",
			BaseURL:        upstream.URL + "/v1",
			APIKey:         "test-key",
			Enabled:        true,
			TimeoutSeconds: 10,
		},
	}
	store := config.NewServerConfigStore(filepath.Join(t.TempDir(), "config.toml"), cfg)
	resolver := NewProviderResolver(store)
	s := &Server{
		store:                 store,
		resolver:              resolver,
		stats:                 NewStatsStore(100),
		providerHealthChecker: NewProviderHealthChecker(resolver, providerHealthCheckInterval),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"test-provider/test-model","input":"hello world"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.proxyHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	summary := s.stats.Summary(time.Hour)
	if summary.TotalTokens <= 0 {
		t.Fatalf("expected fallback token estimate > 0, got %d", summary.TotalTokens)
	}
	if summary.PromptTokens <= 0 {
		t.Fatalf("expected fallback prompt token estimate > 0, got %d", summary.PromptTokens)
	}
	if summary.CompletionTokens <= 0 {
		t.Fatalf("expected fallback completion token estimate > 0, got %d", summary.CompletionTokens)
	}
}

func TestProxyHandlerFallbackEstimatesTokensWithoutUsageStreaming(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"streamed reply\"}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()

	cfg := config.NewDefaultServerConfig()
	cfg.Providers = []config.ProviderConfig{
		{
			Name:           "test-provider",
			BaseURL:        upstream.URL + "/v1",
			APIKey:         "test-key",
			Enabled:        true,
			TimeoutSeconds: 10,
		},
	}
	store := config.NewServerConfigStore(filepath.Join(t.TempDir(), "config.toml"), cfg)
	resolver := NewProviderResolver(store)
	s := &Server{
		store:                 store,
		resolver:              resolver,
		stats:                 NewStatsStore(100),
		providerHealthChecker: NewProviderHealthChecker(resolver, providerHealthCheckInterval),
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"test-provider/test-model","stream":true,"input":"hello world"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.proxyHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	summary := s.stats.Summary(time.Hour)
	if summary.TotalTokens <= 0 {
		t.Fatalf("expected fallback token estimate > 0, got %d", summary.TotalTokens)
	}
	if summary.PromptTokens <= 0 {
		t.Fatalf("expected fallback prompt token estimate > 0, got %d", summary.PromptTokens)
	}
	if summary.CompletionTokens <= 0 {
		t.Fatalf("expected fallback completion token estimate > 0, got %d", summary.CompletionTokens)
	}
}
