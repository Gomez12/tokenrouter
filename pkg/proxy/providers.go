package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/tokenrouter/pkg/config"
	"github.com/lkarlslund/tokenrouter/pkg/provider"
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

const autoProviderProbeTTL = 20 * time.Second

var autoProviderProbeFn = probeAutoProviderOnline

var autoProviderProbeState struct {
	mu    sync.Mutex
	byKey map[string]autoProviderProbeResult
}

type autoProviderProbeResult struct {
	checkedAt time.Time
	online    bool
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
				candidate := p.AsProviderConfig()
				if !autoProviderOnline(candidate) {
					// Keep auto public-free providers virtually disabled until endpoint is reachable.
					continue
				}
				out = append(out, candidate)
				seen[p.Name] = struct{}{}
			}
		}
	}
	return out
}

func autoLMStudioOnline(p config.ProviderConfig) bool {
	return autoProviderOnline(p)
}

func autoProviderOnline(p config.ProviderConfig) bool {
	now := time.Now().UTC()
	key := strings.ToLower(strings.TrimSpace(p.Name)) + "|" + strings.TrimSpace(p.BaseURL)
	autoProviderProbeState.mu.Lock()
	if autoProviderProbeState.byKey == nil {
		autoProviderProbeState.byKey = map[string]autoProviderProbeResult{}
	}
	if prev, ok := autoProviderProbeState.byKey[key]; ok && !prev.checkedAt.IsZero() && now.Sub(prev.checkedAt) < autoProviderProbeTTL {
		online := prev.online
		autoProviderProbeState.mu.Unlock()
		return online
	}
	autoProviderProbeState.mu.Unlock()

	online := false
	if autoProviderProbeFn != nil {
		online = autoProviderProbeFn(p)
	}

	autoProviderProbeState.mu.Lock()
	autoProviderProbeState.byKey[key] = autoProviderProbeResult{
		checkedAt: now,
		online:    online,
	}
	autoProviderProbeState.mu.Unlock()
	return online
}

func probeAutoProviderOnline(p config.ProviderConfig) bool {
	name := strings.ToLower(strings.TrimSpace(p.Name))
	switch name {
	case "lmstudio":
		return probeLMStudioOnline(p)
	case "ollama":
		return probeOllamaOnline(p)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	_, err := NewProviderClient(p).ListModels(ctx)
	return err == nil
}

func probeLMStudioOnline(p config.ProviderConfig) bool {
	baseURL := strings.TrimSpace(p.BaseURL)
	if baseURL == "" {
		return false
	}
	u, err := neturl.Parse(baseURL)
	if err != nil || strings.TrimSpace(u.Scheme) == "" || strings.TrimSpace(u.Host) == "" {
		return false
	}
	root := &neturl.URL{Scheme: u.Scheme, Host: u.Host}
	cli := &http.Client{Timeout: 1200 * time.Millisecond}

	// Reject known Ollama signature quickly; avoids false auto-enable on :1234.
	ollamaURL := *root
	ollamaURL.Path = "/api/tags"
	if req, err := http.NewRequest(http.MethodGet, ollamaURL.String(), nil); err == nil {
		if resp, err := cli.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8*1024))
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
				return false
			}
		}
	}

	// Require LM Studio native endpoint to be present.
	lmsURL := *root
	lmsURL.Path = "/api/v0/models"
	req, err := http.NewRequest(http.MethodGet, lmsURL.String(), nil)
	if err != nil {
		return false
	}
	resp, err := cli.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return false
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return false
	}
	switch decoded.(type) {
	case []any, map[string]any:
		return true
	default:
		return false
	}
}

func probeOllamaOnline(p config.ProviderConfig) bool {
	baseURL := strings.TrimSpace(p.BaseURL)
	if baseURL == "" {
		return false
	}
	u, err := neturl.Parse(baseURL)
	if err != nil || strings.TrimSpace(u.Scheme) == "" || strings.TrimSpace(u.Host) == "" {
		return false
	}
	root := &neturl.URL{Scheme: u.Scheme, Host: u.Host}
	cli := &http.Client{Timeout: 1200 * time.Millisecond}
	tagsURL := *root
	tagsURL.Path = "/api/tags"
	req, err := http.NewRequest(http.MethodGet, tagsURL.String(), nil)
	if err != nil {
		return false
	}
	resp, err := cli.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	var out struct {
		Models []map[string]any `json:"models"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return false
	}
	return out.Models != nil
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
	normalizedModel := normalizeModelID(model)
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
	if preferredProvider := preferredProviderForUnqualifiedModel(normalizedModel, providers); preferredProvider != nil {
		return *preferredProvider, normalizedModel, nil
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
		return p, normalizedModel, nil
	}
	return config.ProviderConfig{}, "", fmt.Errorf("no enabled providers configured")
}

func preferredProviderForUnqualifiedModel(model string, providers []config.ProviderConfig) *config.ProviderConfig {
	model = strings.TrimSpace(strings.ToLower(model))
	if model == "" {
		return nil
	}
	if strings.HasPrefix(model, "gpt-") || strings.HasPrefix(model, "o") {
		for i := range providers {
			p := providers[i]
			name := strings.ToLower(strings.TrimSpace(p.Name))
			providerType := strings.ToLower(strings.TrimSpace(p.ProviderType))
			if name == "openai" || providerType == "openai" {
				return &providers[i]
			}
		}
	}
	return nil
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
