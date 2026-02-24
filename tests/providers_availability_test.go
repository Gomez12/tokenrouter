package tests

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/tokenrouter/pkg/assets"
	"github.com/lkarlslund/tokenrouter/pkg/config"
	"github.com/lkarlslund/tokenrouter/pkg/proxy"
)

func TestPopularProvidersAssetLoads(t *testing.T) {
	providers, err := assets.LoadPopularProviders()
	if err != nil {
		t.Fatalf("load popular providers: %v", err)
	}
	if len(providers) == 0 {
		t.Fatal("expected at least one popular provider")
	}
	for _, p := range providers {
		if p.Name == "" {
			t.Fatalf("provider has empty name: %+v", p)
		}
		if p.BaseURL == "" && strings.TrimSpace(p.BaseURLTemplate) == "" {
			t.Fatalf("provider %q has neither base_url nor base_url_template", p.Name)
		}
	}
}

func TestPopularProvidersAvailability(t *testing.T) {
	providers, err := assets.LoadPopularProviders()
	if err != nil {
		t.Fatalf("load popular providers: %v", err)
	}

	for _, p := range providers {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			t.Parallel()
			baseURL := strings.TrimSpace(p.BaseURL)
			if baseURL == "" {
				baseURL = strings.TrimSpace(p.BaseURLTemplate)
			}
			if baseURL == "" {
				t.Skipf("skipping %s: missing base URL", p.Name)
			}
			if strings.Contains(baseURL, "{") || strings.Contains(baseURL, "}") {
				t.Skipf("skipping %s: base URL template requires substitution (%s)", p.Name, baseURL)
			}

			t.Run("availability", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancel()

				pc := proxy.NewProviderClient(config.ProviderConfig{
					Name:           p.Name,
					BaseURL:        baseURL,
					TimeoutSeconds: 12,
				})
				_, err := pc.ListModels(ctx)
				if err == nil {
					return
				}
				if proxy.IsProviderAuthError(err) || proxy.IsProviderRateLimited(err) {
					return
				}
				t.Fatalf("provider unavailable (%s): %v", p.BaseURL, err)
			})

			t.Run("list_models", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancel()

				pc := proxy.NewProviderClient(config.ProviderConfig{
					Name:           p.Name,
					BaseURL:        baseURL,
					APIKey:         strings.TrimSpace(os.Getenv(p.APIKeyEnv)),
					TimeoutSeconds: 12,
				})
				models, err := pc.ListModels(ctx)
				if proxy.IsProviderAuthError(err) {
					t.Skipf("skipping model listing for %s: provide %s for authenticated listing", p.Name, p.APIKeyEnv)
				}
				if proxy.IsProviderRateLimited(err) {
					t.Skipf("skipping model listing for %s: rate limited (429)", p.Name)
				}
				if err != nil {
					t.Fatalf("provider unavailable (%s): %v", p.BaseURL, err)
				}
				if len(models) == 0 {
					t.Fatalf("no models returned from %s", p.Name)
				}
				ids := make([]string, 0, len(models))
				for _, m := range models {
					ids = append(ids, m.ID)
				}
				if len(ids) == 0 {
					t.Fatalf("no model ids returned from %s", p.Name)
				}
				t.Logf("models for %s (%d): %s", p.Name, len(ids), strings.Join(ids, ", "))
			})
		})
	}
}
