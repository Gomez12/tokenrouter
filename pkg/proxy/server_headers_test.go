package proxy

import (
	"net/http/httptest"
	"testing"

	"github.com/lkarlslund/tokenrouter/pkg/config"
)

func TestApplyUpstreamProviderHeaders_OpenAICodex(t *testing.T) {
	t.Setenv("CODEX_INTERNAL_ORIGINATOR_OVERRIDE", "")
	req := httptest.NewRequest("POST", "http://example.local/v1/responses", nil)
	provider := config.ProviderConfig{
		BaseURL:   "https://chatgpt.com/backend-api",
		AuthToken: "auth-token",
		AccountID: "acct_123",
	}

	applyUpstreamProviderHeaders(req, provider, req.Header.Clone())

	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected content-type application/json, got %q", got)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer auth-token" {
		t.Fatalf("expected auth token header, got %q", got)
	}
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Fatalf("expected accept application/json, got %q", got)
	}
	if got := req.Header.Get("OpenAI-Beta"); got != "responses=experimental" {
		t.Fatalf("expected OpenAI-Beta header, got %q", got)
	}
	if got := req.Header.Get("originator"); got != "codex_cli_rs" {
		t.Fatalf("expected default originator, got %q", got)
	}
	if got := req.Header.Get("User-Agent"); got != "codex-cli/0.104.0" {
		t.Fatalf("expected codex user-agent, got %q", got)
	}
	if got := req.Header.Get("ChatGPT-Account-ID"); got != "acct_123" {
		t.Fatalf("expected ChatGPT-Account-ID, got %q", got)
	}
}

func TestApplyUpstreamProviderHeaders_OriginatorOverrideAndAPIKey(t *testing.T) {
	t.Setenv("CODEX_INTERNAL_ORIGINATOR_OVERRIDE", "custom_origin")
	req := httptest.NewRequest("POST", "http://example.local/v1/responses", nil)
	provider := config.ProviderConfig{
		BaseURL:   "https://chatgpt.com/backend-api",
		APIKey:    "api-key",
		AuthToken: "auth-token",
	}

	applyUpstreamProviderHeaders(req, provider, req.Header.Clone())

	if got := req.Header.Get("Authorization"); got != "Bearer api-key" {
		t.Fatalf("expected api key precedence, got %q", got)
	}
	if got := req.Header.Get("originator"); got != "custom_origin" {
		t.Fatalf("expected custom originator override, got %q", got)
	}
}

func TestApplyUpstreamProviderHeaders_NonCodexProvider(t *testing.T) {
	req := httptest.NewRequest("POST", "http://example.local/v1/chat/completions", nil)
	provider := config.ProviderConfig{
		BaseURL: "https://api.openai.com/v1",
		APIKey:  "sk-test",
	}

	applyUpstreamProviderHeaders(req, provider, req.Header.Clone())

	if got := req.Header.Get("Authorization"); got != "Bearer sk-test" {
		t.Fatalf("expected auth header, got %q", got)
	}
	if got := req.Header.Get("OpenAI-Beta"); got != "" {
		t.Fatalf("did not expect codex beta header, got %q", got)
	}
	if got := req.Header.Get("originator"); got != "" {
		t.Fatalf("did not expect originator header, got %q", got)
	}
	if got := req.Header.Get("User-Agent"); got != "" {
		t.Fatalf("did not expect codex user-agent, got %q", got)
	}
}
