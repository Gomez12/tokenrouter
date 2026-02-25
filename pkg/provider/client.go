package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/lkarlslund/tokenrouter/pkg/config"
)

type ModelCard struct {
	ID       string `json:"id"`
	Object   string `json:"object,omitempty"`
	Provider string `json:"provider,omitempty"`
}

type modelListResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

type HTTPError struct {
	Provider   string
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("provider %s models status %d: %s", e.Provider, e.StatusCode, e.Body)
}

type Client struct {
	Provider config.ProviderConfig
	client   *http.Client
}

func NewClient(p config.ProviderConfig) *Client {
	timeout := p.TimeoutSeconds
	if timeout <= 0 {
		timeout = 60
	}
	return &Client{
		Provider: p,
		client:   &http.Client{Timeout: time.Duration(timeout) * time.Second},
	}
}

func (c *Client) ListModels(ctx context.Context) ([]ModelCard, error) {
	if isOpenAICodexProvider(c.Provider) {
		return codexStaticModels(c.Provider.Name), nil
	}
	providerType := strings.ToLower(strings.TrimSpace(c.Provider.ProviderType))
	name := strings.ToLower(strings.TrimSpace(c.Provider.Name))
	if (providerType == "google-gemini" || name == "google-gemini") &&
		strings.TrimSpace(c.Provider.APIKey) == "" &&
		strings.TrimSpace(c.Provider.AuthToken) != "" {
		return c.listGoogleGeminiOAuthModels(ctx)
	}
	u, err := url.Parse(strings.TrimRight(c.Provider.BaseURL, "/"))
	if err != nil {
		return nil, err
	}
	u.Path = JoinProviderPath(u.Path, "/v1/models")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	token := strings.TrimSpace(c.Provider.APIKey)
	if token == "" {
		token = strings.TrimSpace(c.Provider.AuthToken)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if isOpenAICodexProvider(c.Provider) && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed) {
			return codexStaticModels(c.Provider.Name), nil
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, &HTTPError{
			Provider:   c.Provider.Name,
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(b)),
		}
	}
	var out modelListResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	cards := make([]ModelCard, 0, len(out.Data))
	for _, m := range out.Data {
		modelID := NormalizeModelID(m.ID)
		cards = append(cards, ModelCard{
			ID:       c.Provider.Name + "/" + modelID,
			Object:   "model",
			Provider: c.Provider.Name,
		})
	}
	return cards, nil
}

func (c *Client) listGoogleGeminiOAuthModels(ctx context.Context) ([]ModelCard, error) {
	modelListURL := strings.TrimSpace(c.Provider.ModelListURL)
	if modelListURL == "" {
		return nil, fmt.Errorf("model_list_url is required for google-gemini oauth providers")
	}
	u, err := url.Parse(modelListURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	token := strings.TrimSpace(c.Provider.AuthToken)
	if token == "" {
		return nil, fmt.Errorf("missing auth token")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(c.Provider.AccountID) != "" {
		req.Header.Set("x-goog-user-project", strings.TrimSpace(c.Provider.AccountID))
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, &HTTPError{
			Provider:   c.Provider.Name,
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(b)),
		}
	}
	var out struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	cards := make([]ModelCard, 0, len(out.Models))
	for _, m := range out.Models {
		modelID := NormalizeModelID(strings.TrimSpace(m.Name))
		if modelID == "" {
			continue
		}
		cards = append(cards, ModelCard{
			ID:       c.Provider.Name + "/" + modelID,
			Object:   "model",
			Provider: c.Provider.Name,
		})
	}
	return cards, nil
}

func codexStaticModels(providerName string) []ModelCard {
	ids := []string{"gpt-5-codex", "gpt-5", "gpt-5-mini", "gpt-5-nano", "o4-mini"}
	out := make([]ModelCard, 0, len(ids))
	for _, id := range ids {
		out = append(out, ModelCard{
			ID:       providerName + "/" + id,
			Object:   "model",
			Provider: providerName,
		})
	}
	return out
}

func IsAuthError(err error) bool {
	httpErr, ok := err.(*HTTPError)
	if !ok {
		return false
	}
	if IsBlocked(err) {
		return false
	}
	if httpErr.StatusCode == http.StatusUnauthorized || httpErr.StatusCode == http.StatusForbidden {
		return true
	}
	if httpErr.StatusCode != http.StatusBadRequest {
		return false
	}
	msg := strings.ToLower(httpErr.Body)
	return strings.Contains(msg, "missing authorization header") ||
		strings.Contains(msg, "invalid api key") ||
		strings.Contains(msg, "api key not valid") ||
		strings.Contains(msg, "authentication") ||
		strings.Contains(msg, "no api key supplied")
}

func IsBlocked(err error) bool {
	httpErr, ok := err.(*HTTPError)
	if !ok {
		return false
	}
	if httpErr.StatusCode != http.StatusForbidden && httpErr.StatusCode != http.StatusTooManyRequests {
		return false
	}
	msg := strings.ToLower(httpErr.Body)
	return strings.Contains(msg, "just a moment") ||
		strings.Contains(msg, "__cf_chl") ||
		strings.Contains(msg, "challenge-platform") ||
		strings.Contains(msg, "cloudflare")
}

func IsRateLimited(err error) bool {
	httpErr, ok := err.(*HTTPError)
	return ok && httpErr.StatusCode == http.StatusTooManyRequests
}

func SplitModelPrefix(model string) (provider string, stripped string, ok bool) {
	parts := strings.SplitN(model, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", model, false
	}
	return parts[0], parts[1], true
}

func NormalizeModelID(model string) string {
	model = strings.TrimSpace(model)
	if strings.HasPrefix(model, "models/") {
		return strings.TrimPrefix(model, "models/")
	}
	return model
}

func JoinProviderPath(basePath, requestPath string) string {
	base := path.Clean("/" + strings.TrimSpace(basePath))
	req := path.Clean("/" + strings.TrimSpace(requestPath))
	if strings.HasSuffix(base, "/v1") && strings.HasPrefix(req, "/v1/") {
		return path.Join(base, strings.TrimPrefix(req, "/v1/"))
	}
	return path.Join(base, req)
}

func isOpenAICodexProvider(provider config.ProviderConfig) bool {
	base := strings.TrimSpace(provider.BaseURL)
	if base == "" {
		return false
	}
	u, err := url.Parse(base)
	if err != nil {
		baseLower := strings.ToLower(base)
		return strings.Contains(baseLower, "chatgpt.com/backend-api") || strings.Contains(baseLower, "/backend-api")
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	pathLower := strings.ToLower(strings.Trim(strings.TrimSpace(u.Path), "/"))
	return host == "chatgpt.com" || strings.Contains(pathLower, "backend-api")
}
