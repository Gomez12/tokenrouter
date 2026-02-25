package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lkarlslund/tokenrouter/pkg/config"
)

func TestListProvidersIncludesPublicFreeWhenEnabled(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	cfg.Providers = nil
	cfg.AutoEnablePublicFreeModels = true
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	r := NewProviderResolver(store)

	providers := r.ListProviders()
	if len(providers) == 0 {
		t.Fatal("expected at least one provider when auto public free models is enabled")
	}
	found := false
	for _, p := range providers {
		if p.Name == "opencode-zen" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected opencode-zen to be included in auto-enabled public free providers")
	}
	for _, p := range providers {
		if p.Name == "nvidia" {
			t.Fatal("did not expect nvidia to be auto-enabled because it requires auth")
		}
	}
}

func TestResolveWithAutoPublicFreeProvider(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	cfg.Providers = nil
	cfg.AutoEnablePublicFreeModels = true
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	r := NewProviderResolver(store)

	p, model, err := r.Resolve("opencode-zen/gpt-5-nano")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if p.Name != "opencode-zen" {
		t.Fatalf("expected opencode-zen provider, got %q", p.Name)
	}
	if model != "gpt-5-nano" {
		t.Fatalf("expected stripped model gpt-5-nano, got %q", model)
	}
}

func TestListProvidersResolvesConfiguredPresetDefaults(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	cfg.AutoEnablePublicFreeModels = false
	cfg.Providers = []config.ProviderConfig{
		{
			Name:    "opencode-zen",
			APIKey:  "x",
			Enabled: true,
		},
	}
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	r := NewProviderResolver(store)

	providers := r.ListProviders()
	if len(providers) != 1 {
		t.Fatalf("expected one provider, got %d", len(providers))
	}
	if providers[0].Name != "opencode-zen" {
		t.Fatalf("expected opencode-zen, got %q", providers[0].Name)
	}
	if providers[0].BaseURL == "" {
		t.Fatal("expected base_url to be resolved from preset defaults")
	}
	if providers[0].TimeoutSeconds <= 0 {
		t.Fatal("expected timeout_seconds to be defaulted")
	}
}

func TestProviderClientUsesAuthTokenWhenAPIKeyEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer device-token" {
			t.Fatalf("expected bearer device token, got %q", got)
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"m"}]}`))
	}))
	defer srv.Close()
	p := config.ProviderConfig{Name: "x", BaseURL: srv.URL, AuthToken: "device-token", Enabled: true, TimeoutSeconds: 2}
	models, err := NewProviderClient(p).ListModels(context.Background())
	if err != nil {
		t.Fatalf("list models: %v", err)
	}
	if len(models) != 1 {
		t.Fatalf("expected one model, got %d", len(models))
	}
	if models[0].ID != "x/m" {
		t.Fatalf("expected model ID x/m, got %q", models[0].ID)
	}
}

func TestProviderClientReturnsStaticModelsForCodexProvider(t *testing.T) {
	p := config.ProviderConfig{
		Name:      "openai",
		BaseURL:   "https://chatgpt.com/backend-api",
		AuthToken: "oauth-token",
		Enabled:   true,
	}
	models, err := NewProviderClient(p).ListModels(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(models) < 5 {
		t.Fatalf("expected at least 5 static codex models, got %d", len(models))
	}
	if models[0].Provider != "openai" {
		t.Fatalf("expected provider openai, got %q", models[0].Provider)
	}
}

func TestIsProviderBlockedCloudflareChallenge(t *testing.T) {
	err := &ProviderHTTPError{
		Provider:   "openai",
		StatusCode: http.StatusForbidden,
		Body:       "<html><title>Just a moment...</title>__cf_chl_tk=abc</html>",
	}
	if !IsProviderBlocked(err) {
		t.Fatal("expected cloudflare challenge to be classified as blocked")
	}
	if IsProviderAuthError(err) {
		t.Fatal("expected blocked challenge not to be classified as auth problem")
	}
}

func TestProviderClientNormalizesModelsPrefix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"models/gemini-2.5-flash"}]}`))
	}))
	defer srv.Close()
	p := config.ProviderConfig{Name: "google-gemini", BaseURL: srv.URL, Enabled: true, TimeoutSeconds: 2}
	models, err := NewProviderClient(p).ListModels(context.Background())
	if err != nil {
		t.Fatalf("list models: %v", err)
	}
	if len(models) != 1 {
		t.Fatalf("expected one model, got %d", len(models))
	}
	if models[0].ID != "google-gemini/gemini-2.5-flash" {
		t.Fatalf("expected normalized model ID, got %q", models[0].ID)
	}
}

func TestResolveNormalizesModelsPrefix(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	cfg.Providers = []config.ProviderConfig{
		{Name: "google-gemini", BaseURL: "https://generativelanguage.googleapis.com/v1beta/openai", APIKey: "x", Enabled: true},
	}
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	r := NewProviderResolver(store)

	p, model, err := r.Resolve("google-gemini/models/gemini-2.5-flash")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if p.Name != "google-gemini" {
		t.Fatalf("expected google-gemini provider, got %q", p.Name)
	}
	if model != "gemini-2.5-flash" {
		t.Fatalf("expected normalized model, got %q", model)
	}
}

func TestListProvidersResolvesPresetDefaultsUsingProviderType(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	cfg.AutoEnablePublicFreeModels = false
	cfg.Providers = []config.ProviderConfig{
		{
			Name:         "openai-work",
			ProviderType: "openai",
			APIKey:       "x",
			Enabled:      true,
		},
	}
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	r := NewProviderResolver(store)

	providers := r.ListProviders()
	if len(providers) != 1 {
		t.Fatalf("expected one provider, got %d", len(providers))
	}
	if providers[0].Name != "openai-work" {
		t.Fatalf("expected openai-work, got %q", providers[0].Name)
	}
	if providers[0].ProviderType != "openai" {
		t.Fatalf("expected provider_type openai, got %q", providers[0].ProviderType)
	}
	if providers[0].BaseURL == "" {
		t.Fatal("expected base_url to be resolved from openai preset via provider_type")
	}
}

func TestResolvePrefersOpenAIProviderForUnqualifiedGPTModel(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	cfg.Providers = []config.ProviderConfig{
		{Name: "groq", BaseURL: "https://api.groq.com/openai/v1", APIKey: "x", Enabled: true},
		{Name: "openai", BaseURL: "https://chatgpt.com/backend-api", AuthToken: "tok", Enabled: true},
	}
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	r := NewProviderResolver(store)

	p, model, err := r.Resolve("gpt-5.3-codex")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if p.Name != "openai" {
		t.Fatalf("expected openai provider for unqualified gpt model, got %q", p.Name)
	}
	if model != "gpt-5.3-codex" {
		t.Fatalf("expected model unchanged, got %q", model)
	}
}
