package config

import (
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestProviderConfigTOMLOmitsEmptyFields(t *testing.T) {
	cfg := ServerConfig{
		ListenAddr:      ":8080",
		IncomingAPIKeys: []string{"k"},
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
