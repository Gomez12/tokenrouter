package config

import (
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
)

func TestProviderConfigTOMLOmitsEmptyFields(t *testing.T) {
	cfg := ServerConfig{
		ListenAddr: ":8080",
		IncomingTokens: []IncomingAPIToken{
			{ID: "tok-1", Name: "Token 1", Key: "k"},
		},
		Providers: []ProviderConfig{
			{
				Name: "openai-main",
			},
		},
	}
	cfg.Normalize()
	b, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	s := string(b)
	for _, forbidden := range []string{
		"\nprovider_type = ''\n",
		"\nbase_url = ''\n",
		"\nmodel_list_url = ''\n",
		"\napi_key = ''\n",
		"\nauth_token = ''\n",
		"\nrefresh_token = ''\n",
		"\ntoken_expires_at = ''\n",
		"\naccount_id = ''\n",
		"\ndevice_auth_url = ''\n",
	} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("found unexpected blank field %q in TOML:\n%s", forbidden, s)
		}
	}
}

func TestIncomingTokenQuotaValidationRejectsSubordinateQuota(t *testing.T) {
	cfg := NewDefaultServerConfig()
	cfg.IncomingTokens = []IncomingAPIToken{
		{
			ID:       "owner",
			Name:     "Owner",
			Key:      "owner-key",
			Role:     TokenRoleInferrer,
			ParentID: "root",
			Quota: &TokenQuota{
				Requests: &TokenQuotaBudget{Limit: 100},
			},
		},
	}
	cfg.Normalize()
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "cannot define quota") {
		t.Fatalf("expected subordinate quota validation error, got %v", err)
	}
}

func TestIncomingTokenQuotaNormalizeClampAndValidateWindow(t *testing.T) {
	cfg := NewDefaultServerConfig()
	cfg.IncomingTokens = []IncomingAPIToken{
		{
			ID:   "root",
			Name: "Root",
			Key:  "root-key",
			Role: TokenRoleInferrer,
			Quota: &TokenQuota{
				Requests: &TokenQuotaBudget{
					Limit:           10,
					IntervalSeconds: -5,
					Used:            99,
					WindowStartedAt: time.Now().UTC().Format(time.RFC3339),
				},
			},
		},
	}
	cfg.Normalize()
	got := cfg.IncomingTokens[0].Quota.Requests
	if got == nil {
		t.Fatal("expected requests quota")
	}
	if got.IntervalSeconds != 0 {
		t.Fatalf("expected interval clamped to 0, got %d", got.IntervalSeconds)
	}
	if got.Used != 10 {
		t.Fatalf("expected used clamped to limit (10), got %d", got.Used)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected validate success, got %v", err)
	}
}
