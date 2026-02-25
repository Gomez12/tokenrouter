package proxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/tokenrouter/pkg/config"
)

func TestSecuritySettingsAPI_TriggersImmediateAccessTokenCleanup(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	cfg.AutoRemoveExpiredTokens = false
	cfg.AutoRemoveEmptyQuotaTokens = false
	cfg.IncomingTokens = []config.IncomingAPIToken{
		{
			ID:        "expired",
			Name:      "expired",
			Key:       "k1",
			Role:      config.TokenRoleInferrer,
			ExpiresAt: "2026-01-01T00:00:00Z",
		},
	}
	store := config.NewServerConfigStore(filepath.Join(t.TempDir(), "config.toml"), cfg)
	s := &Server{store: store}
	h := &AdminHandler{store: store}

	cleanupCalled := false
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	h.SetAccessTokenCleanup(func() {
		cleanupCalled = true
		_, _ = s.cleanupAccessTokens(now)
	})

	req := httptest.NewRequest(http.MethodPut, "/admin/api/settings/security", strings.NewReader(`{
		"allow_localhost_no_auth": false,
		"allow_host_docker_internal_no_auth": false,
		"auto_enable_public_free_models": true,
		"auto_remove_expired_tokens": true,
		"auto_remove_empty_quota_tokens": false
	}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.securitySettingsAPI(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if !cleanupCalled {
		t.Fatal("expected immediate cleanup callback to be invoked")
	}
	snap := store.Snapshot()
	if len(snap.IncomingTokens) != 0 {
		t.Fatalf("expected expired token to be removed immediately, got %d tokens", len(snap.IncomingTokens))
	}
}
