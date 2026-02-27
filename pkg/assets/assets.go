package assets

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"path"
	"strings"

	"github.com/lkarlslund/tokenrouter/pkg/config"
)

//go:embed files/templates/*.html files/templates/tab/*.html files/popular-providers.json files/static/*
var FS embed.FS

type PopularProvider struct {
	config.ProviderConfig
	DisplayName              string              `json:"display_name"`
	DocsURL                  string              `json:"docs_url"`
	APIKeyEnv                string              `json:"api_key_env"`
	Compatibility            string              `json:"compatibility"`
	PublicFreeNoAuth         bool                `json:"public_free_no_auth,omitempty"`
	FreeTierWithKey          bool                `json:"free_tier_with_key,omitempty"`
	TrialCredits             bool                `json:"trial_credits,omitempty"`
	GetAPIKeyURL             string              `json:"get_api_key_url,omitempty"`
	AuthPortalURL            string              `json:"auth_portal_url,omitempty"`
	DeviceBindingURL         string              `json:"device_binding_url,omitempty"`
	DeviceCodeURL            string              `json:"device_code_url,omitempty"`
	DeviceTokenURL           string              `json:"device_token_url,omitempty"`
	DeviceClientID           string              `json:"device_client_id,omitempty"`
	DeviceScope              string              `json:"device_scope,omitempty"`
	DeviceGrantType          string              `json:"device_grant_type,omitempty"`
	DeviceCodeParam          string              `json:"device_code_param,omitempty"`
	OAuthAuthorizeURL        string              `json:"oauth_authorize_url,omitempty"`
	OAuthTokenURL            string              `json:"oauth_token_url,omitempty"`
	OAuthClientID            string              `json:"oauth_client_id,omitempty"`
	OAuthClientSecret        string              `json:"oauth_client_secret,omitempty"`
	OAuthScope               string              `json:"oauth_scope,omitempty"`
	OAuthBaseURL             string              `json:"oauth_base_url,omitempty"`
	OAuthOriginator          string              `json:"oauth_originator,omitempty"`
	QuotaReader              string              `json:"quota_reader,omitempty"`
	QuotaProbeModels         []string            `json:"quota_probe_models,omitempty"`
	PricingURL               string              `json:"pricing_url,omitempty"`
	PricingModelsURL         string              `json:"pricing_models_url,omitempty"`
	PricingGatherer          string              `json:"pricing_gatherer,omitempty"`
	QuotaIncludedByMetric    bool                `json:"quota_included_by_metric,omitempty"`
	QuotaMetricFeatureIgnore []string            `json:"quota_metric_feature_ignore,omitempty"`
	QuotaFreeByPlan          map[string][]string `json:"quota_free_models_by_plan,omitempty"`
	BaseURLTemplate          string              `json:"base_url_template,omitempty"`
	BaseURLHint              string              `json:"base_url_hint,omitempty"`
	BaseURLExample           string              `json:"base_url_example,omitempty"`
	SourceURL                string              `json:"source_url,omitempty"`
	LastVerifiedAt           string              `json:"last_verified_at,omitempty"`
}

func (p PopularProvider) AsProviderConfig() config.ProviderConfig {
	cfg := p.ProviderConfig
	if cfg.Name == "" {
		cfg.Name = p.Name
	}
	if cfg.ProviderType == "" {
		cfg.ProviderType = p.Name
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = p.BaseURL
	}
	cfg.Enabled = true
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = 30
	}
	if cfg.DeviceAuthURL == "" {
		cfg.DeviceAuthURL = p.DeviceBindingURL
	}
	return cfg
}

func ParseTemplates() (*template.Template, error) {
	t, err := template.ParseFS(FS, "files/templates/*.html", "files/templates/tab/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse embedded templates: %w", err)
	}
	return t, nil
}

func LoadPopularProviders() ([]PopularProvider, error) {
	b, err := FS.ReadFile("files/popular-providers.json")
	if err != nil {
		return nil, fmt.Errorf("read popular providers: %w", err)
	}
	var providers []PopularProvider
	if err := json.Unmarshal(b, &providers); err != nil {
		return nil, fmt.Errorf("decode popular providers: %w", err)
	}
	return providers, nil
}

func LoadStaticAsset(name string) ([]byte, error) {
	clean := strings.TrimPrefix(path.Clean("/"+name), "/")
	if clean == "" || clean == "." || strings.HasPrefix(clean, "..") {
		return nil, fmt.Errorf("invalid static asset name")
	}
	b, err := FS.ReadFile("files/static/" + clean)
	if err != nil {
		return nil, fmt.Errorf("read static asset: %w", err)
	}
	return b, nil
}
