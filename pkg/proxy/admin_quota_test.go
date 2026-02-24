package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/tokenrouter/pkg/assets"
	"github.com/lkarlslund/tokenrouter/pkg/cache"
	"github.com/lkarlslund/tokenrouter/pkg/config"
)

func TestReadOpenAICodexQuotaParsesUsagePayload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/backend-api/wham/usage" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token-123" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"plan_type":"pro",
			"rate_limit":{"primary_window":{"used_percent":42,"limit_window_seconds":300,"reset_at":1735689600}},
			"additional_rate_limits":[{"metered_feature":"codex","rate_limit":{"primary_window":{"used_percent":70,"limit_window_seconds":300,"reset_at":1735693200}}}]
		}`))
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:      "openai-main",
		BaseURL:   srv.URL + "/backend-api",
		AuthToken: "token-123",
	}
	snap := h.readOpenAICodexQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "openai",
		Reader:       "openai_codex",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "ok" {
		t.Fatalf("expected ok status, got %+v", snap)
	}
	if snap.LeftPercent != 30 {
		t.Fatalf("expected left_percent 30, got %v", snap.LeftPercent)
	}
	if snap.PlanType != "pro" {
		t.Fatalf("expected plan_type pro, got %q", snap.PlanType)
	}
	if snap.ResetAt == "" {
		t.Fatal("expected reset_at to be set")
	}
	if len(snap.Metrics) == 0 {
		t.Fatal("expected parsed quota metrics")
	}
}

func TestReadOpenAICodexQuotaParsesMultipleWindowsAndFeatures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"plan_type":"pro",
			"additional_rate_limits":[
				{
					"metered_feature":"codex",
					"rate_limit":{
						"primary_window":{"used_percent":2,"limit_window_seconds":18000,"reset_at":1735693200},
						"secondary_window":{"used_percent":13,"limit_window_seconds":604800,"reset_at":1736200000}
					}
				},
				{
					"metered_feature":"gpt-5.3-codex-spark",
					"rate_limit":{
						"primary_window":{"used_percent":0,"limit_window_seconds":18000,"reset_at":1735693200},
						"secondary_window":{"used_percent":0,"limit_window_seconds":604800,"reset_at":1736200000}
					}
				}
			]
		}`))
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:      "openai-main",
		BaseURL:   srv.URL + "/backend-api",
		AuthToken: "token-123",
	}
	snap := h.readOpenAICodexQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "openai",
		Reader:       "openai_codex",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "ok" {
		t.Fatalf("expected ok status, got %+v", snap)
	}
	if len(snap.Metrics) != 4 {
		t.Fatalf("expected 4 quota metrics, got %d (%+v)", len(snap.Metrics), snap.Metrics)
	}
}

func TestReadProviderQuotaCachedUsesTTL(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"plan_type":"plus","rate_limit":{"primary_window":{"used_percent":25,"limit_window_seconds":300,"reset_at":1735689600}}}`))
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:      "openai-work",
		BaseURL:   srv.URL,
		AuthToken: "token-abc",
	}
	preset := assets.PopularProvider{
		ProviderConfig: config.ProviderConfig{Name: "openai"},
		DisplayName:    "OpenAI",
		QuotaReader:    "openai_codex",
	}
	snap1 := h.readProviderQuotaCached(context.Background(), p, preset)
	snap2 := h.readProviderQuotaCached(context.Background(), p, preset)
	if snap1.Status != "ok" || snap2.Status != "ok" {
		t.Fatalf("expected ok snapshots, got %+v %+v", snap1, snap2)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected one upstream quota request due to cache, got %d", got)
	}
}

func TestReadGoogleAntigravityQuotaParsesMetrics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1internal:loadCodeAssist" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer google-token" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"paidTier": map[string]any{
				"id": "g1-pro-tier",
			},
			"quota_windows": []any{
				map[string]any{
					"meteredFeature":      "gemini-pro",
					"window":              "5h",
					"remainingPercent":    98.0,
					"usedPercent":         2.0,
					"quotaResetTimeStamp": "2026-02-23T20:49:36Z",
				},
				map[string]any{
					"meteredFeature":      "gemini-pro",
					"window":              "7d",
					"remainingPercent":    87.0,
					"usedPercent":         13.0,
					"quotaResetTimeStamp": "2026-02-27T12:44:20Z",
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:      "google-gemini",
		BaseURL:   srv.URL + "/v1internal",
		AuthToken: "google-token",
	}
	snap := h.readGoogleAntigravityQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "google-gemini",
		Reader:       "google_antigravity",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "ok" {
		t.Fatalf("expected ok status, got %+v", snap)
	}
	if snap.PlanType != "g1-pro-tier" {
		t.Fatalf("expected plan g1-pro-tier, got %q", snap.PlanType)
	}
	if len(snap.Metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(snap.Metrics))
	}
}

func TestReadGoogleAntigravityQuotaUsesRetrieveUserQuota(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1internal:retrieveUserQuota":
			if got := r.Header.Get("Authorization"); got != "Bearer google-token" {
				t.Fatalf("unexpected auth header: %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]any{
				"buckets": []any{
					map[string]any{
						"remainingFraction": 0.91,
						"resetTime":         "2026-02-23T20:49:36Z",
						"tokenType":         "REQUESTS",
						"modelId":           "gemini-2.5-pro",
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:      "google-gemini",
		BaseURL:   srv.URL + "/v1internal",
		AuthToken: "google-token",
		AccountID: "projects/test-project",
	}
	snap := h.readGoogleAntigravityQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "google-gemini",
		Reader:       "google_antigravity",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "ok" {
		t.Fatalf("expected ok status, got %+v", snap)
	}
	if len(snap.Metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(snap.Metrics))
	}
	if snap.LeftPercent <= 0 || snap.LeftPercent > 100 {
		t.Fatalf("unexpected left percent: %v", snap.LeftPercent)
	}
}

func TestReadGoogleAntigravityQuotaReturnsRetrieveErrorWhenNoQuotaFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1internal:loadCodeAssist":
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]any{
				"currentTier":             map[string]any{"id": "free-tier"},
				"cloudaicompanionProject": "projects/demo-project",
			}
			_ = json.NewEncoder(w).Encode(resp)
		case "/v1internal:retrieveUserQuota":
			http.Error(w, `{"error":{"code":403,"message":"The caller does not have permission","status":"PERMISSION_DENIED"}}`, http.StatusForbidden)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:      "google-gemini",
		BaseURL:   srv.URL + "/v1internal",
		AuthToken: "google-token",
	}
	snap := h.readGoogleAntigravityQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "google-gemini",
		Reader:       "google_antigravity",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "error" {
		t.Fatalf("expected error status, got %+v", snap)
	}
	if !strings.Contains(strings.ToLower(snap.Error), "permission") {
		t.Fatalf("expected permission error, got %q", snap.Error)
	}
}

func TestComputeProviderQuotaAndStoreRefreshesExpiredGoogleOAuthToken(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "refresh_token" {
			t.Fatalf("unexpected grant_type: %q", got)
		}
		if got := r.Form.Get("refresh_token"); got != "refresh-1" {
			t.Fatalf("unexpected refresh token: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","expires_in":3600}`))
	}))
	defer tokenSrv.Close()

	antigravitySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer new-access" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		switch r.URL.Path {
		case "/v1internal:retrieveUserQuota":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"buckets":[{"remainingFraction":0.75,"resetTime":"2026-02-24T00:00:00Z","tokenType":"REQUESTS","modelId":"gemini-2.5-pro"}]}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer antigravitySrv.Close()

	cfg := config.NewDefaultServerConfig()
	cfg.Providers = []config.ProviderConfig{
		{
			Name:           "google-gemini",
			ProviderType:   "google-gemini",
			BaseURL:        antigravitySrv.URL + "/v1internal",
			AuthToken:      "expired-access",
			RefreshToken:   "refresh-1",
			TokenExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
			AccountID:      "projects/demo-project",
			Enabled:        true,
		},
	}
	store := config.NewServerConfigStore(filepath.Join(t.TempDir(), "config.toml"), cfg)
	h := &AdminHandler{
		store:      store,
		quotaCache: cache.NewTTLMap[string, quotaCacheValue](),
	}
	p := cfg.Providers[0]
	preset := assets.PopularProvider{
		ProviderConfig: config.ProviderConfig{
			Name: "google-gemini",
		},
		DisplayName:       "Google Gemini",
		QuotaReader:       "google_antigravity",
		OAuthTokenURL:     tokenSrv.URL,
		OAuthClientID:     "client-id",
		OAuthClientSecret: "client-secret",
	}
	snap := h.computeProviderQuotaAndStore(p, preset)
	if snap.Status != "ok" {
		t.Fatalf("expected ok status, got %+v", snap)
	}
	updated := store.Snapshot()
	if got := strings.TrimSpace(updated.Providers[0].AuthToken); got != "new-access" {
		t.Fatalf("expected refreshed auth token to be stored, got %q", got)
	}
}

func TestReadGroqQuotaParsesRateLimitHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openai/v1/models" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer gsk-test" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		w.Header().Set("x-ratelimit-limit-requests", "10000")
		w.Header().Set("x-ratelimit-remaining-requests", "8700")
		w.Header().Set("x-ratelimit-reset-requests", "2m30s")
		w.Header().Set("x-ratelimit-limit-tokens", "200000")
		w.Header().Set("x-ratelimit-remaining-tokens", "150000")
		w.Header().Set("x-ratelimit-reset-tokens", "45s")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"x"}]}`))
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:    "groq-main",
		BaseURL: srv.URL + "/openai/v1",
		APIKey:  "gsk-test",
	}
	snap := h.readGroqQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "groq",
		Reader:       "groq_headers",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "ok" {
		t.Fatalf("expected ok status, got %+v", snap)
	}
	if len(snap.Metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(snap.Metrics))
	}
	if snap.LeftPercent <= 0 || snap.LeftPercent > 100 {
		t.Fatalf("unexpected left percent: %v", snap.LeftPercent)
	}
}

func TestReadGroqQuotaFallsBackToTinyChatForHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openai/v1/models":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"llama-3.1-8b-instant"}]}`))
		case "/openai/v1/chat/completions":
			w.Header().Set("x-ratelimit-limit-requests", "100")
			w.Header().Set("x-ratelimit-remaining-requests", "80")
			w.Header().Set("x-ratelimit-reset-requests", "1m")
			w.Header().Set("x-ratelimit-limit-tokens", "10000")
			w.Header().Set("x-ratelimit-remaining-tokens", "9000")
			w.Header().Set("x-ratelimit-reset-tokens", "30s")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"cmpl","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:    "groq-main",
		BaseURL: srv.URL + "/openai/v1",
		APIKey:  "gsk-test",
	}
	snap := h.readGroqQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "groq",
		Reader:       "groq_headers",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "ok" {
		t.Fatalf("expected ok status, got %+v", snap)
	}
	if len(snap.Metrics) != 2 {
		t.Fatalf("expected 2 metrics after fallback, got %d", len(snap.Metrics))
	}
}

func TestReadMistralQuotaParsesRateLimitHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer mistral-key" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		w.Header().Set("x-ratelimit-limit-requests-minute", "120")
		w.Header().Set("x-ratelimit-remaining-requests-minute", "84")
		w.Header().Set("x-ratelimit-reset-requests-minute", "30s")
		w.Header().Set("x-ratelimit-limit-tokens-minute", "60000")
		w.Header().Set("x-ratelimit-remaining-tokens-minute", "51000")
		w.Header().Set("x-ratelimit-reset-tokens-minute", "15s")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"mistral-small-latest"}]}`))
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:    "mistral-main",
		BaseURL: srv.URL + "/v1",
		APIKey:  "mistral-key",
	}
	snap := h.readMistralQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "mistral",
		Reader:       "mistral_headers",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "ok" {
		t.Fatalf("expected ok status, got %+v", snap)
	}
	if len(snap.Metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(snap.Metrics))
	}
	if snap.LeftPercent <= 0 || snap.LeftPercent > 100 {
		t.Fatalf("unexpected left percent: %v", snap.LeftPercent)
	}
}

func TestReadMistralQuotaReturnsErrorWhenHeadersMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"mistral-small-latest"}]}`))
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:    "mistral-main",
		BaseURL: srv.URL + "/v1",
		APIKey:  "mistral-key",
	}
	snap := h.readMistralQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "mistral",
		Reader:       "mistral_headers",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "error" {
		t.Fatalf("expected error status, got %+v", snap)
	}
	if snap.Error != "quota headers unavailable" {
		t.Fatalf("unexpected error: %q", snap.Error)
	}
}

func TestReadMistralQuotaFallsBackToTinyChatForHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"mistral-small-latest"}]}`))
		case "/v1/chat/completions":
			w.Header().Set("x-ratelimit-limit-requests-minute", "120")
			w.Header().Set("x-ratelimit-remaining-requests-minute", "90")
			w.Header().Set("x-ratelimit-reset-requests-minute", "20s")
			w.Header().Set("x-ratelimit-limit-tokens-minute", "60000")
			w.Header().Set("x-ratelimit-remaining-tokens-minute", "57000")
			w.Header().Set("x-ratelimit-reset-tokens-minute", "10s")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"chatcmpl","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:    "mistral-main",
		BaseURL: srv.URL + "/v1",
		APIKey:  "mistral-key",
	}
	snap := h.readMistralQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "mistral",
		Reader:       "mistral_headers",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "ok" {
		t.Fatalf("expected ok status, got %+v", snap)
	}
	if len(snap.Metrics) != 2 {
		t.Fatalf("expected 2 metrics after fallback, got %d", len(snap.Metrics))
	}
}

func TestReadMistralQuotaResetFallbackFromFeatureLevelHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("x-ratelimit-limit-requests-minute", "120")
		w.Header().Set("x-ratelimit-remaining-requests-minute", "84")
		w.Header().Set("x-ratelimit-reset-requests", "45s")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"mistral-small-latest"}]}`))
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:    "mistral-main",
		BaseURL: srv.URL + "/v1",
		APIKey:  "mistral-key",
	}
	snap := h.readMistralQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "mistral",
		Reader:       "mistral_headers",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "ok" {
		t.Fatalf("expected ok status, got %+v", snap)
	}
	if len(snap.Metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(snap.Metrics))
	}
	if snap.Metrics[0].ResetAt == "" {
		t.Fatalf("expected reset_at from feature-level fallback header, got empty metric=%+v", snap.Metrics[0])
	}
}

func TestReadHuggingFaceQuotaParsesLegacyRateLimitHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer hf_test_token" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		w.Header().Set("x-ratelimit-limit-requests-minute", "600")
		w.Header().Set("x-ratelimit-remaining-requests-minute", "450")
		w.Header().Set("x-ratelimit-reset-requests-minute", "30s")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"meta-llama/Llama-3.1-8B-Instruct"}]}`))
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:    "huggingface-main",
		BaseURL: srv.URL + "/v1",
		APIKey:  "hf_test_token",
	}
	snap := h.readHuggingFaceQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "huggingface",
		Reader:       "huggingface_headers",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "ok" {
		t.Fatalf("expected ok status, got %+v", snap)
	}
	if len(snap.Metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(snap.Metrics))
	}
	if snap.LeftPercent != 75 {
		t.Fatalf("expected left_percent 75, got %v", snap.LeftPercent)
	}
}

func TestReadHuggingFaceQuotaParsesGenericRateLimitHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("x-ratelimit-limit", "100")
		w.Header().Set("x-ratelimit-remaining", "80")
		w.Header().Set("x-ratelimit-reset", "30s")
		w.Header().Set("x-ratelimit-limit-tokens", "10000")
		w.Header().Set("x-ratelimit-remaining-tokens", "9000")
		w.Header().Set("x-ratelimit-reset-tokens", "15s")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"meta-llama/Llama-3.1-8B-Instruct"}]}`))
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:    "huggingface-main",
		BaseURL: srv.URL + "/v1",
		APIKey:  "hf_test_token",
	}
	snap := h.readHuggingFaceQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "huggingface",
		Reader:       "huggingface_headers",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "ok" {
		t.Fatalf("expected ok status, got %+v", snap)
	}
	if len(snap.Metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d (%+v)", len(snap.Metrics), snap.Metrics)
	}
	if snap.LeftPercent != 80 {
		t.Fatalf("expected left_percent 80, got %v", snap.LeftPercent)
	}
}

func TestReadHuggingFaceQuotaParsesStructuredRateLimitHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("RateLimit", `"api";r=750;t=90`)
		w.Header().Set("RateLimit-Policy", `"api";q=1000;w=300`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"Qwen/Qwen3-Coder-480B-A35B-Instruct"}]}`))
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:    "huggingface-main",
		BaseURL: srv.URL + "/v1",
		APIKey:  "hf_test_token",
	}
	snap := h.readHuggingFaceQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "huggingface",
		Reader:       "huggingface_headers",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "ok" {
		t.Fatalf("expected ok status, got %+v", snap)
	}
	if len(snap.Metrics) != 1 {
		t.Fatalf("expected 1 structured metric, got %d (%+v)", len(snap.Metrics), snap.Metrics)
	}
	if snap.LeftPercent <= 0 || snap.LeftPercent > 100 {
		t.Fatalf("unexpected left percent: %v", snap.LeftPercent)
	}
	if snap.Metrics[0].MeteredFeature != "api" {
		t.Fatalf("expected metered feature api, got %q", snap.Metrics[0].MeteredFeature)
	}
}

func TestReadHuggingFaceQuotaFallsBackToTinyChatForHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"meta-llama/Llama-3.1-8B-Instruct"}]}`))
		case "/v1/chat/completions":
			w.Header().Set("x-ratelimit-limit-requests-minute", "600")
			w.Header().Set("x-ratelimit-remaining-requests-minute", "540")
			w.Header().Set("x-ratelimit-reset-requests-minute", "20s")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"chatcmpl","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:    "huggingface-main",
		BaseURL: srv.URL + "/v1",
		APIKey:  "hf_test_token",
	}
	snap := h.readHuggingFaceQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "huggingface",
		Reader:       "huggingface_headers",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "ok" {
		t.Fatalf("expected ok status after tiny chat fallback, got %+v", snap)
	}
	if len(snap.Metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(snap.Metrics))
	}
}

func TestReadHuggingFaceQuotaTinyChatTriesMultipleModels(t *testing.T) {
	var chatCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"not-chat-model"},{"id":"Qwen/Qwen2.5-7B-Instruct"}]}`))
		case "/v1/chat/completions":
			chatCalls++
			body, _ := io.ReadAll(io.LimitReader(r.Body, 8*1024))
			if strings.Contains(string(body), `"model":"not-chat-model"`) {
				http.Error(w, `{"error":"unsupported model"}`, http.StatusBadRequest)
				return
			}
			w.Header().Set("x-ratelimit-limit", "100")
			w.Header().Set("x-ratelimit-remaining", "70")
			w.Header().Set("x-ratelimit-reset", "20s")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"chatcmpl","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:    "huggingface-main",
		BaseURL: srv.URL + "/v1",
		APIKey:  "hf_test_token",
	}
	snap := h.readHuggingFaceQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "huggingface",
		Reader:       "huggingface_headers",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "ok" {
		t.Fatalf("expected ok status after trying multiple models, got %+v", snap)
	}
	if chatCalls < 2 {
		t.Fatalf("expected at least 2 chat attempts, got %d", chatCalls)
	}
	if len(snap.Metrics) == 0 {
		t.Fatalf("expected quota metrics, got none")
	}
}

func TestReadCerebrasQuotaParsesRateLimitHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer csk-test" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		w.Header().Set("x-ratelimit-limit-requests-day", "250000")
		w.Header().Set("x-ratelimit-remaining-requests-day", "200000")
		w.Header().Set("x-ratelimit-reset-requests-day", "3600")
		w.Header().Set("x-ratelimit-limit-tokens-minute", "1200000")
		w.Header().Set("x-ratelimit-remaining-tokens-minute", "900000")
		w.Header().Set("x-ratelimit-reset-tokens-minute", "45")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"llama-3.3-70b"}]}`))
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:    "cerebras-main",
		BaseURL: srv.URL + "/v1",
		APIKey:  "csk-test",
	}
	snap := h.readCerebrasQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "cerebras",
		Reader:       "cerebras_headers",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "ok" {
		t.Fatalf("expected ok status, got %+v", snap)
	}
	if len(snap.Metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d (%+v)", len(snap.Metrics), snap.Metrics)
	}
	if snap.LeftPercent <= 0 || snap.LeftPercent > 100 {
		t.Fatalf("unexpected left percent: %v", snap.LeftPercent)
	}
	for _, m := range snap.Metrics {
		if m.ResetAt == "" {
			t.Fatalf("expected reset_at to be populated for metric %+v", m)
		}
	}
}

func TestReadCerebrasQuotaFallsBackToTinyChatForHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"llama-3.3-70b"}]}`))
		case "/v1/chat/completions":
			w.Header().Set("x-ratelimit-limit-requests-day", "250000")
			w.Header().Set("x-ratelimit-remaining-requests-day", "245000")
			w.Header().Set("x-ratelimit-reset-requests-day", "3600")
			w.Header().Set("x-ratelimit-limit-tokens-minute", "1200000")
			w.Header().Set("x-ratelimit-remaining-tokens-minute", "1100000")
			w.Header().Set("x-ratelimit-reset-tokens-minute", "45")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"chatcmpl","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:    "cerebras-main",
		BaseURL: srv.URL + "/v1",
		APIKey:  "csk-test",
	}
	snap := h.readCerebrasQuota(context.Background(), p, ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "cerebras",
		Reader:       "cerebras_headers",
		Status:       "error",
		CheckedAt:    time.Now().UTC().Format(time.RFC3339),
	})
	if snap.Status != "ok" {
		t.Fatalf("expected ok status after tiny chat fallback, got %+v", snap)
	}
	if len(snap.Metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d (%+v)", len(snap.Metrics), snap.Metrics)
	}
}

func TestRecordQuotaFromResponseUpdatesCacheForHeaderReaders(t *testing.T) {
	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:         "groq-main",
		ProviderType: "groq",
	}
	headers := http.Header{}
	headers.Set("x-ratelimit-limit-requests", "1000")
	headers.Set("x-ratelimit-remaining-requests", "800")
	headers.Set("x-ratelimit-reset-requests", "45s")
	headers.Set("x-ratelimit-limit-tokens", "100000")
	headers.Set("x-ratelimit-remaining-tokens", "90000")
	headers.Set("x-ratelimit-reset-tokens", "30s")

	h.RecordQuotaFromResponse(p, headers)

	entry, _, ok := h.quotaCache.Get(p.Name)
	if !ok {
		t.Fatal("expected quota cache entry to be populated")
	}
	if entry.Snapshot.Status != "ok" {
		t.Fatalf("expected ok status, got %+v", entry.Snapshot)
	}
	if len(entry.Snapshot.Metrics) != 2 {
		t.Fatalf("expected 2 metrics, got %d", len(entry.Snapshot.Metrics))
	}
	if entry.Snapshot.LeftPercent <= 0 || entry.Snapshot.LeftPercent > 100 {
		t.Fatalf("unexpected left percent: %v", entry.Snapshot.LeftPercent)
	}
}

func TestComputeProviderQuotaAndStorePreservesLastGoodSnapshotOnRefreshError(t *testing.T) {
	h := &AdminHandler{quotaCache: cache.NewTTLMap[string, quotaCacheValue]()}
	p := config.ProviderConfig{
		Name:         "mistral-main",
		ProviderType: "mistral",
		BaseURL:      "http://127.0.0.1:0/v1",
		APIKey:       "mistral-key",
	}
	preset := assets.PopularProvider{
		ProviderConfig: config.ProviderConfig{Name: "mistral"},
		DisplayName:    "Mistral",
		QuotaReader:    "mistral_headers",
	}
	now := time.Now().UTC()
	lastGood := ProviderQuotaSnapshot{
		Provider:     p.Name,
		ProviderType: "mistral",
		DisplayName:  "Mistral",
		Reader:       "mistral_headers",
		Status:       "ok",
		CheckedAt:    now.Add(-2 * time.Hour).Format(time.RFC3339),
		PlanType:     "mistral",
		LeftPercent:  88,
		Metrics: []ProviderQuotaMetric{
			{Key: "mistral:requests-minute", MeteredFeature: "requests", Window: "1m", LeftPercent: 88},
		},
	}
	h.quotaCache.SetWithTTL(p.Name, quotaCacheValue{
		Snapshot:   lastGood,
		Refreshing: false,
	}, now.Add(-2*time.Hour), quotaRefreshOK)

	got := h.computeProviderQuotaAndStore(p, preset)
	if got.Status != "ok" {
		t.Fatalf("expected preserved ok snapshot, got %+v", got)
	}
	if got.LeftPercent != 88 {
		t.Fatalf("expected preserved left percent 88, got %v", got.LeftPercent)
	}
	cached, _, ok := h.quotaCache.Get(p.Name)
	if !ok {
		t.Fatal("expected quota cache entry")
	}
	if cached.Snapshot.Status != "ok" || cached.Snapshot.LeftPercent != 88 {
		t.Fatalf("expected preserved cached snapshot, got %+v", cached.Snapshot)
	}
}

func TestQuotaModelIsIncluded(t *testing.T) {
	quota := map[string]ProviderQuotaSnapshot{
		"google-gemini": {
			Status: "ok",
			Metrics: []ProviderQuotaMetric{
				{MeteredFeature: "gemini-2.5-pro"},
			},
		},
		"openai": {
			Status:   "ok",
			PlanType: "pro",
			Metrics:  []ProviderQuotaMetric{{MeteredFeature: "codex"}},
		},
	}
	popular := map[string]assets.PopularProvider{
		"google-gemini": {
			QuotaIncludedByMetric:    true,
			QuotaMetricFeatureIgnore: []string{"gemini", "requests", "tokens"},
		},
		"openai": {
			QuotaIncludedByMetric: false,
			QuotaFreeByPlan: map[string][]string{
				"pro": {"gpt-5-codex"},
			},
		},
	}
	if !quotaModelIsIncluded("google-gemini", "google-gemini", "gemini-2.5-pro", quota, popular) {
		t.Fatal("expected gemini model to be included from quota metric")
	}
	if !quotaModelIsIncluded("openai", "openai", "gpt-5-codex", quota, popular) {
		t.Fatal("expected openai model to be included from plan rule")
	}
	if quotaModelIsIncluded("openai", "openai", "gpt-4o", quota, popular) {
		t.Fatal("did not expect unrelated model to be marked as included")
	}
}
