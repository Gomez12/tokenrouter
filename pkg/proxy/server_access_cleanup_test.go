package proxy

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/lkarlslund/tokenrouter/pkg/config"
)

func TestCleanupAccessTokens_RemovesExpiredAndEmptyQuotaAndOrphans(t *testing.T) {
	isolateDefaultDataPaths(t)
	cfg := config.NewDefaultServerConfig()
	cfg.AutoRemoveExpiredTokens = true
	cfg.AutoRemoveEmptyQuotaTokens = true
	cfg.IncomingTokens = []config.IncomingAPIToken{
		{ID: "expired-parent", Name: "expired", Key: "k1", Role: config.TokenRoleInferrer, ExpiresAt: "2026-01-01T00:00:00Z"},
		{ID: "child", Name: "child", Key: "k2", Role: config.TokenRoleInferrer, ParentID: "expired-parent"},
		{ID: "empty-quota", Name: "empty", Key: "k3", Role: config.TokenRoleInferrer, Quota: &config.TokenQuota{Requests: &config.TokenQuotaBudget{Limit: 100, Used: 100, IntervalSeconds: 0}}},
		{ID: "resetting-quota", Name: "resetting", Key: "k4", Role: config.TokenRoleInferrer, Quota: &config.TokenQuota{Requests: &config.TokenQuotaBudget{Limit: 100, Used: 100, IntervalSeconds: 3600}}},
		{ID: "ok", Name: "ok", Key: "k5", Role: config.TokenRoleInferrer},
	}

	s, err := NewServer(filepath.Join(t.TempDir(), "config.toml"), cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	res, err := s.cleanupAccessTokens(now)
	if err != nil {
		t.Fatalf("cleanupAccessTokens: %v", err)
	}
	if res.ExpiredTokens != 1 {
		t.Fatalf("expected 1 expired token removed, got %d", res.ExpiredTokens)
	}
	if res.EmptyQuotaTokens != 1 {
		t.Fatalf("expected 1 empty quota token removed, got %d", res.EmptyQuotaTokens)
	}
	if res.OrphanedTokens != 1 {
		t.Fatalf("expected 1 orphaned token removed, got %d", res.OrphanedTokens)
	}

	snap := s.store.Snapshot()
	if len(snap.IncomingTokens) != 2 {
		t.Fatalf("expected 2 tokens remaining, got %d", len(snap.IncomingTokens))
	}
	ids := map[string]struct{}{}
	for _, tok := range snap.IncomingTokens {
		ids[tok.ID] = struct{}{}
	}
	if _, ok := ids["resetting-quota"]; !ok {
		t.Fatal("expected resetting-quota token to remain")
	}
	if _, ok := ids["ok"]; !ok {
		t.Fatal("expected ok token to remain")
	}
}

func TestCleanupAccessTokens_DisabledSettingsNoChanges(t *testing.T) {
	isolateDefaultDataPaths(t)
	cfg := config.NewDefaultServerConfig()
	cfg.AutoRemoveExpiredTokens = false
	cfg.AutoRemoveEmptyQuotaTokens = false
	cfg.IncomingTokens = []config.IncomingAPIToken{
		{ID: "expired", Name: "expired", Key: "k1", Role: config.TokenRoleInferrer, ExpiresAt: "2026-01-01T00:00:00Z"},
		{ID: "empty", Name: "empty", Key: "k2", Role: config.TokenRoleInferrer, Quota: &config.TokenQuota{Requests: &config.TokenQuotaBudget{Limit: 1, Used: 1, IntervalSeconds: 0}}},
	}

	s, err := NewServer(filepath.Join(t.TempDir(), "config.toml"), cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	res, err := s.cleanupAccessTokens(now)
	if err != nil {
		t.Fatalf("cleanupAccessTokens: %v", err)
	}
	if res.ExpiredTokens != 0 || res.EmptyQuotaTokens != 0 || res.OrphanedTokens != 0 {
		t.Fatalf("expected zero removals, got %+v", res)
	}
	snap := s.store.Snapshot()
	if len(snap.IncomingTokens) != 2 {
		t.Fatalf("expected 2 tokens remaining, got %d", len(snap.IncomingTokens))
	}
}
