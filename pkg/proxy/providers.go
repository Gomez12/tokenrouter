package proxy

import (
	"context"
	"fmt"
	"strings"

	"github.com/lkarlslund/openai-personal-proxy/pkg/config"
	"github.com/lkarlslund/openai-personal-proxy/pkg/provider"
)

type ModelCard = provider.ModelCard
type ProviderHTTPError = provider.HTTPError

func NewProviderClient(p config.ProviderConfig) *provider.Client {
	return provider.NewClient(p)
}

func IsProviderAuthError(err error) bool {
	return provider.IsAuthError(err)
}

func IsProviderBlocked(err error) bool {
	return provider.IsBlocked(err)
}

func IsProviderRateLimited(err error) bool {
	return provider.IsRateLimited(err)
}

func splitModelPrefix(model string) (providerName string, stripped string, ok bool) {
	return provider.SplitModelPrefix(model)
}

func normalizeModelID(model string) string {
	return provider.NormalizeModelID(model)
}

func joinProviderPath(basePath, requestPath string) string {
	return provider.JoinProviderPath(basePath, requestPath)
}

type ProviderResolver struct {
	store *config.ServerConfigStore
}

func NewProviderResolver(store *config.ServerConfigStore) *ProviderResolver {
	return &ProviderResolver{store: store}
}

func (r *ProviderResolver) ListProviders() []config.ProviderConfig {
	cfg := r.store.Snapshot()
	out := make([]config.ProviderConfig, 0, len(cfg.Providers))
	seen := map[string]struct{}{}
	popularByName := map[string]config.ProviderConfig{}
	if popular, err := getPopularProviders(); err == nil {
		for _, p := range popular {
			popularByName[p.Name] = p.AsProviderConfig()
		}
	}
	for _, p := range cfg.Providers {
		if p.Enabled {
			presetKey := providerTypeOrName(p)
			resolved := resolveProviderWithDefaults(p, popularByName[presetKey])
			seen[resolved.Name] = struct{}{}
			out = append(out, resolved)
		}
	}
	if cfg.AutoEnablePublicFreeModels {
		popular, err := getPopularProviders()
		if err == nil {
			for _, p := range popular {
				if !p.PublicFreeNoAuth {
					continue
				}
				if _, ok := seen[p.Name]; ok {
					continue
				}
				out = append(out, p.AsProviderConfig())
				seen[p.Name] = struct{}{}
			}
		}
	}
	return out
}

func resolveProviderWithDefaults(p config.ProviderConfig, preset config.ProviderConfig) config.ProviderConfig {
	if strings.TrimSpace(p.BaseURL) == "" {
		p.BaseURL = preset.BaseURL
	}
	if strings.TrimSpace(p.ModelListURL) == "" {
		p.ModelListURL = preset.ModelListURL
	}
	if strings.TrimSpace(p.DeviceAuthURL) == "" {
		p.DeviceAuthURL = preset.DeviceAuthURL
	}
	if p.TimeoutSeconds <= 0 {
		if preset.TimeoutSeconds > 0 {
			p.TimeoutSeconds = preset.TimeoutSeconds
		} else {
			p.TimeoutSeconds = 60
		}
	}
	return p
}

func providerTypeOrName(p config.ProviderConfig) string {
	if strings.TrimSpace(p.ProviderType) != "" {
		return strings.TrimSpace(p.ProviderType)
	}
	return strings.TrimSpace(p.Name)
}

func (r *ProviderResolver) GetProviderByName(name string) (config.ProviderConfig, bool) {
	for _, p := range r.ListProviders() {
		if p.Name == name {
			return p, true
		}
	}
	return config.ProviderConfig{}, false
}

func (r *ProviderResolver) Resolve(model string) (config.ProviderConfig, string, error) {
	providers := r.ListProviders()
	if model != "" {
		if providerName, stripped, ok := splitModelPrefix(model); ok {
			stripped = normalizeModelID(stripped)
			for _, p := range providers {
				if p.Name == providerName {
					return p, stripped, nil
				}
			}
		}
	}
	cfg := r.store.Snapshot()
	if cfg.DefaultProvider != "" {
		for _, p := range providers {
			if p.Name == cfg.DefaultProvider {
				return p, model, nil
			}
		}
	}
	for _, p := range providers {
		return p, normalizeModelID(model), nil
	}
	return config.ProviderConfig{}, "", fmt.Errorf("no enabled providers configured")
}

func (r *ProviderResolver) DiscoverModels(ctx context.Context) ([]ModelCard, error) {
	providers := r.ListProviders()
	models := make([]ModelCard, 0)
	for _, p := range providers {
		cards, err := NewProviderClient(p).ListModels(ctx)
		if err != nil {
			continue
		}
		models = append(models, cards...)
	}
	return models, nil
}
