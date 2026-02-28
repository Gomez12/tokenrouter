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

func TestModelAliasesTOMLRoundTrip(t *testing.T) {
	cfg := NewDefaultServerConfig()
	cfg.ActiveModelProfile = "local"
	cfg.ModelAliases = []ModelAliasConfig{
		{
			Name: "chat",
			Targets: []ModelAliasTarget{
				{Profile: "runpod", Provider: "runpod-main", Model: "Qwen/Qwen2.5-14B-Instruct"},
				{Profile: "local", Provider: "ollama", Model: "qwen2.5:14b"},
			},
		},
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	raw, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded ServerConfig
	if err := toml.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	decoded.Normalize()
	if err := decoded.Validate(); err != nil {
		t.Fatalf("validate decoded: %v", err)
	}
	if decoded.ActiveModelProfile != "local" {
		t.Fatalf("expected active profile local, got %q", decoded.ActiveModelProfile)
	}
	if len(decoded.ModelAliases) != 1 {
		t.Fatalf("expected one alias, got %d", len(decoded.ModelAliases))
	}
	if decoded.ModelAliases[0].Name != "chat" {
		t.Fatalf("expected alias chat, got %q", decoded.ModelAliases[0].Name)
	}
	if len(decoded.ModelAliases[0].Targets) != 2 {
		t.Fatalf("expected two targets, got %d", len(decoded.ModelAliases[0].Targets))
	}
	if decoded.ModelAliases[0].Targets[0].Profile != "local" {
		t.Fatalf("expected targets to be normalized/sorted with local first, got %+v", decoded.ModelAliases[0].Targets)
	}
}

func TestModelAliasValidationRejectsSlashName(t *testing.T) {
	cfg := NewDefaultServerConfig()
	cfg.ActiveModelProfile = "local"
	cfg.ModelAliases = []ModelAliasConfig{
		{Name: "ollama/chat", Targets: []ModelAliasTarget{{Profile: "local", Provider: "ollama", Model: "qwen"}}},
	}
	cfg.Normalize()
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "cannot contain /") {
		t.Fatalf("expected slash-name validation error, got %v", err)
	}
}

func TestModelAliasValidationRejectsDuplicateAlias(t *testing.T) {
	cfg := NewDefaultServerConfig()
	cfg.ActiveModelProfile = "local"
	cfg.ModelAliases = []ModelAliasConfig{
		{Name: "chat", Targets: []ModelAliasTarget{{Profile: "local", Provider: "ollama", Model: "qwen"}}},
		{Name: "chat", Targets: []ModelAliasTarget{{Profile: "runpod", Provider: "runpod-main", Model: "Qwen"}}},
	}
	cfg.Normalize()
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate model alias") {
		t.Fatalf("expected duplicate alias validation error, got %v", err)
	}
}

func TestModelAliasValidationRejectsDuplicateProfile(t *testing.T) {
	cfg := NewDefaultServerConfig()
	cfg.ActiveModelProfile = "local"
	cfg.ModelAliases = []ModelAliasConfig{
		{
			Name: "chat",
			Targets: []ModelAliasTarget{
				{Profile: "local", Provider: "ollama", Model: "qwen-a"},
				{Profile: "local", Provider: "ollama", Model: "qwen-b"},
			},
		},
	}
	cfg.Normalize()
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate profile") {
		t.Fatalf("expected duplicate profile validation error, got %v", err)
	}
}

func TestModelAliasValidationRequiresActiveProfile(t *testing.T) {
	cfg := NewDefaultServerConfig()
	cfg.ModelAliases = []ModelAliasConfig{
		{Name: "chat", Targets: []ModelAliasTarget{{Profile: "local", Provider: "ollama", Model: "qwen"}}},
	}
	cfg.Normalize()
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "active_model_profile is required") {
		t.Fatalf("expected active profile validation error, got %v", err)
	}
}

func TestModelAliasValidationAllowsUnknownProvider(t *testing.T) {
	cfg := NewDefaultServerConfig()
	cfg.ActiveModelProfile = "runpod"
	cfg.ModelAliases = []ModelAliasConfig{
		{
			Name: "chat",
			Targets: []ModelAliasTarget{
				{Profile: "runpod", Provider: "runpod-main", Model: "Qwen/Qwen2.5-14B-Instruct"},
			},
		},
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected unknown provider to validate, got %v", err)
	}
}

func TestRoleAtLeastHierarchy(t *testing.T) {
	tests := []struct {
		name     string
		actual   string
		required string
		ok       bool
	}{
		{name: "admin satisfies keymaster", actual: TokenRoleAdmin, required: TokenRoleKeymaster, ok: true},
		{name: "admin satisfies inferrer", actual: TokenRoleAdmin, required: TokenRoleInferrer, ok: true},
		{name: "keymaster satisfies inferrer", actual: TokenRoleKeymaster, required: TokenRoleInferrer, ok: true},
		{name: "keymaster does not satisfy admin", actual: TokenRoleKeymaster, required: TokenRoleAdmin, ok: false},
		{name: "inferrer does not satisfy keymaster", actual: TokenRoleInferrer, required: TokenRoleKeymaster, ok: false},
		{name: "blank normalizes to inferrer", actual: "", required: TokenRoleInferrer, ok: true},
		{name: "unknown role rejected", actual: "owner", required: TokenRoleInferrer, ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := RoleAtLeast(tc.actual, tc.required); got != tc.ok {
				t.Fatalf("RoleAtLeast(%q, %q)=%v want %v", tc.actual, tc.required, got, tc.ok)
			}
		})
	}
}
