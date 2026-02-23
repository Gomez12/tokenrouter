package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultServerConfigPathUsesConfigToml(t *testing.T) {
	if got := filepath.Base(DefaultServerConfigPath()); got != defaultConfigFileName {
		t.Fatalf("expected default config file %q, got %q", defaultConfigFileName, got)
	}
}

func TestLoadServerConfigFallsBackToLegacyAndMigrates(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, legacyConfigFileName)
	current := filepath.Join(dir, defaultConfigFileName)

	cfg := NewDefaultServerConfig()
	cfg.IncomingTokens = []IncomingAPIToken{{ID: "tok-1", Name: "Token 1", Key: "k"}}
	cfg.IncomingAPIKeys = []string{"k"}
	cfg.AdminAPIKey = "admin"
	cfg.Providers = []ProviderConfig{{Name: "openai-main", Enabled: true}}
	if err := Save(legacy, cfg); err != nil {
		t.Fatalf("save legacy config: %v", err)
	}
	if _, err := os.Stat(current); !os.IsNotExist(err) {
		t.Fatalf("expected %s not to exist before load, err=%v", current, err)
	}

	loaded, err := LoadServerConfig(current)
	if err != nil {
		t.Fatalf("load with legacy fallback failed: %v", err)
	}
	if loaded.AdminAPIKey != "admin" {
		t.Fatalf("unexpected loaded admin key: %q", loaded.AdminAPIKey)
	}
	if _, err := os.Stat(current); err != nil {
		t.Fatalf("expected migrated config at %s: %v", current, err)
	}
	b, err := os.ReadFile(current)
	if err != nil {
		t.Fatalf("read migrated config: %v", err)
	}
	if !strings.Contains(string(b), "[[providers]]") {
		t.Fatalf("expected providers table in migrated config:\n%s", string(b))
	}
}
