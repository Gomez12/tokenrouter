package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lkarlslund/tokenrouter/pkg/assets"
	"github.com/lkarlslund/tokenrouter/pkg/config"
)

func refreshOAuthTokenForProvider(ctx context.Context, store *config.ServerConfigStore, p config.ProviderConfig) config.ProviderConfig {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(p.RefreshToken) == "" {
		return p
	}
	expiresAt := strings.TrimSpace(p.TokenExpiresAt)
	token := strings.TrimSpace(p.AuthToken)
	if expiresAt != "" && token != "" {
		if ts, err := time.Parse(time.RFC3339, expiresAt); err == nil && time.Until(ts) > 60*time.Second {
			return p
		}
	}

	preset, ok := oauthPresetForProvider(p)
	if !ok {
		return p
	}
	tokenURL := strings.TrimSpace(preset.OAuthTokenURL)
	clientID := strings.TrimSpace(preset.OAuthClientID)
	clientSecret := strings.TrimSpace(preset.OAuthClientSecret)
	if tokenURL == "" || clientID == "" {
		return p
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", strings.TrimSpace(p.RefreshToken))
	form.Set("client_id", clientID)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return p
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return p
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return p
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return p
	}
	if strings.TrimSpace(out.AccessToken) == "" {
		return p
	}
	p.AuthToken = strings.TrimSpace(out.AccessToken)
	if strings.TrimSpace(out.RefreshToken) != "" {
		p.RefreshToken = strings.TrimSpace(out.RefreshToken)
	}
	if out.ExpiresIn > 0 {
		p.TokenExpiresAt = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
	}
	if store != nil {
		_ = store.Update(func(c *config.ServerConfig) error {
			for i := range c.Providers {
				if c.Providers[i].Name != p.Name {
					continue
				}
				c.Providers[i].AuthToken = p.AuthToken
				c.Providers[i].RefreshToken = p.RefreshToken
				c.Providers[i].TokenExpiresAt = p.TokenExpiresAt
				break
			}
			return nil
		})
	}
	return p
}

func oauthPresetForProvider(p config.ProviderConfig) (assets.PopularProvider, bool) {
	popular, err := getPopularProviders()
	if err != nil {
		return assets.PopularProvider{}, false
	}
	key := strings.TrimSpace(providerTypeOrName(p))
	for _, pp := range popular {
		if strings.EqualFold(strings.TrimSpace(pp.Name), key) {
			return pp, true
		}
	}
	name := strings.TrimSpace(p.Name)
	for _, pp := range popular {
		if strings.EqualFold(strings.TrimSpace(pp.Name), name) {
			return pp, true
		}
	}
	return assets.PopularProvider{}, false
}
