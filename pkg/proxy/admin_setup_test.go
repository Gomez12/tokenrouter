package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lkarlslund/tokenrouter/pkg/config"
)

func TestLoginRedirectsToSetupWhenAdminKeyMissing(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	store := config.NewServerConfigStore(filepath.Join(t.TempDir(), "config.toml"), cfg)
	h := &AdminHandler{store: store}

	req := httptest.NewRequest(http.MethodGet, "/admin/login?next=/admin", nil)
	w := httptest.NewRecorder()
	h.login(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/admin/setup" {
		t.Fatalf("expected redirect to /admin/setup, got %q", loc)
	}
}

func TestSetupSavesAdminKeyAndRedirectsToAdmin(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	store := config.NewServerConfigStore(filepath.Join(t.TempDir(), "config.toml"), cfg)
	h := &AdminHandler{store: store}

	form := url.Values{}
	form.Set("key", "super-secret-admin-key")
	form.Set("confirm_key", "super-secret-admin-key")
	req := httptest.NewRequest(http.MethodPost, "/admin/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.setup(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d body=%s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/admin" {
		t.Fatalf("expected redirect to /admin, got %q", loc)
	}
	gotCfg := store.Snapshot()
	if len(gotCfg.IncomingTokens) != 1 {
		t.Fatalf("expected one created incoming token, got %d", len(gotCfg.IncomingTokens))
	}
	if gotCfg.IncomingTokens[0].Role != config.TokenRoleAdmin {
		t.Fatalf("expected created token role admin, got %q", gotCfg.IncomingTokens[0].Role)
	}
	if gotCfg.IncomingTokens[0].Key != "super-secret-admin-key" {
		t.Fatalf("expected created token key persisted")
	}
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == adminSessionCookie && c.Value == "super-secret-admin-key" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected %s cookie to be set", adminSessionCookie)
	}
}
