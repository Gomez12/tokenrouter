package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lkarlslund/tokenrouter/pkg/config"
)

func TestProviderClientListModelsGoogleGeminiOAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer oauth-token" {
			t.Fatalf("unexpected authorization: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"models":[{"name":"models/gemini-2.5-pro"},{"name":"models/gemini-2.5-flash"}]}`))
	}))
	defer srv.Close()

	c := NewProviderClient(config.ProviderConfig{
		Name:         "google-gemini",
		BaseURL:      "https://generativelanguage.googleapis.com/v1beta/openai",
		ModelListURL: srv.URL + "/v1/models",
		AuthToken:    "oauth-token",
	})
	models, err := c.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels returned error: %v", err)
	}
	if len(models) != 2 {
		t.Fatalf("expected 2 models, got %d", len(models))
	}
	if models[0].ID != "google-gemini/gemini-2.5-pro" {
		t.Fatalf("unexpected first model: %+v", models[0])
	}
}

func TestProviderClientListModelsGoogleGeminiOAuthReturnsErrorOnScopeFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			w.WriteHeader(http.StatusForbidden)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"error":{"status":"PERMISSION_DENIED","message":"Request had insufficient authentication scopes.","details":[{"reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT"}]}}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := NewProviderClient(config.ProviderConfig{
		Name:         "google-gemini",
		ProviderType: "google-gemini",
		BaseURL:      srv.URL + "/v1internal",
		ModelListURL: srv.URL + "/v1/models",
		AuthToken:    "oauth-token",
	})
	models, err := c.ListModels(context.Background())
	if err == nil {
		t.Fatalf("expected error, got models=%v", models)
	}
}
