package proxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/lkarlslund/tokenrouter/pkg/config"
)

func TestLoginRendersWhenAdminKeyMissing(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	cfg.IncomingTokens = nil
	store := config.NewServerConfigStore(filepath.Join(t.TempDir(), "config.toml"), cfg)
	h := &AdminHandler{store: store}

	req := httptest.NewRequest(http.MethodGet, "/admin/login?next=/admin", nil)
	w := httptest.NewRecorder()
	h.login(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected login page 200, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestLegacySetupPathRedirectsToAdmin(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	store := config.NewServerConfigStore(filepath.Join(t.TempDir(), "config.toml"), cfg)
	h := &AdminHandler{store: store}

	req := httptest.NewRequest(http.MethodGet, "/admin/setup", nil)
	w := httptest.NewRecorder()
	h.legacySetupRedirect(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("expected redirect status, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/admin" {
		t.Fatalf("expected redirect to /admin, got %q", loc)
	}
}

func TestFirstRunLocalhostCanOpenAdminWithoutAuth(t *testing.T) {
	isolateDefaultDataPaths(t)
	cfg := config.NewDefaultServerConfig()
	cfg.IncomingTokens = nil
	cfg.AllowLocalhostNoAuth = true
	s, err := NewServer(filepath.Join(t.TempDir(), "config.toml"), cfg)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for /admin on localhost first run, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestFirstRunLocalhostCanUseAccessTokensAPIWithoutAuth(t *testing.T) {
	isolateDefaultDataPaths(t)
	cfg := config.NewDefaultServerConfig()
	cfg.IncomingTokens = nil
	cfg.AllowLocalhostNoAuth = true
	s, err := NewServer(filepath.Join(t.TempDir(), "config.toml"), cfg)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/api/access-tokens", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for /admin/api/access-tokens on localhost first run, got %d body=%s", w.Code, w.Body.String())
	}
}
