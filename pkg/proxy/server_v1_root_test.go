package proxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/lkarlslund/tokenrouter/pkg/config"
)

func TestV1RootAndModelsRequireAuth(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	cfg.AllowLocalhostNoAuth = false
	cfg.IncomingTokens = nil
	s, err := NewServer(filepath.Join(t.TempDir(), "torod.toml"), cfg)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	reqRoot := httptest.NewRequest(http.MethodGet, "/v1/", nil)
	wRoot := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(wRoot, reqRoot)
	if wRoot.Code != http.StatusUnauthorized {
		t.Fatalf("expected /v1/ status 401, got %d body=%s", wRoot.Code, wRoot.Body.String())
	}

	reqModels := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	wModels := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(wModels, reqModels)
	if wModels.Code != http.StatusUnauthorized {
		t.Fatalf("expected /v1/models status 401, got %d body=%s", wModels.Code, wModels.Body.String())
	}
}
