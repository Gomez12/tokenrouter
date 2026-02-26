package proxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/lkarlslund/tokenrouter/pkg/config"
)

func TestV1RootAndModelsRequireAuth(t *testing.T) {
	isolateDefaultDataPaths(t)
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

func TestV1StatusAuthByRole(t *testing.T) {
	isolateDefaultDataPaths(t)
	cfg := config.NewDefaultServerConfig()
	cfg.AllowLocalhostNoAuth = false
	cfg.IncomingTokens = []config.IncomingAPIToken{
		{ID: "adm", Name: "Admin", Key: "adm-key", Role: config.TokenRoleAdmin},
		{ID: "km", Name: "Keymaster", Key: "km-key", Role: config.TokenRoleKeymaster},
		{ID: "inf", Name: "Inferrer", Key: "inf-key", Role: config.TokenRoleInferrer},
	}
	s, err := NewServer(filepath.Join(t.TempDir(), "torod.toml"), cfg)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	reqNoAuth := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	wNoAuth := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(wNoAuth, reqNoAuth)
	if wNoAuth.Code != http.StatusUnauthorized {
		t.Fatalf("expected /v1/status status 401 without auth, got %d body=%s", wNoAuth.Code, wNoAuth.Body.String())
	}

	for _, tc := range []struct {
		name string
		key  string
	}{
		{name: "admin", key: "adm-key"},
		{name: "keymaster", key: "km-key"},
		{name: "inferrer", key: "inf-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
			req.Header.Set("Authorization", "Bearer "+tc.key)
			w := httptest.NewRecorder()
			s.httpServer.Handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("expected /v1/status status 200, got %d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestV1ModelsAuthByRoleHierarchy(t *testing.T) {
	isolateDefaultDataPaths(t)
	cfg := config.NewDefaultServerConfig()
	cfg.AllowLocalhostNoAuth = false
	cfg.IncomingTokens = []config.IncomingAPIToken{
		{ID: "adm", Name: "Admin", Key: "adm-key", Role: config.TokenRoleAdmin},
		{ID: "km", Name: "Keymaster", Key: "km-key", Role: config.TokenRoleKeymaster},
		{ID: "inf", Name: "Inferrer", Key: "inf-key", Role: config.TokenRoleInferrer},
	}
	s, err := NewServer(filepath.Join(t.TempDir(), "torod.toml"), cfg)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	for _, tc := range []struct {
		name string
		key  string
	}{
		{name: "admin", key: "adm-key"},
		{name: "keymaster", key: "km-key"},
		{name: "inferrer", key: "inf-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
			req.Header.Set("Authorization", "Bearer "+tc.key)
			w := httptest.NewRecorder()
			s.httpServer.Handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("expected /v1/models status 200, got %d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
