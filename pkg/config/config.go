package config

import (
	"bytes"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pelletier/go-toml/v2"
)

const (
	defaultConfigFileName = "torod.toml"

	TokenRoleAdmin     = "admin"
	TokenRoleKeymaster = "keymaster"
	TokenRoleInferrer  = "inferrer"
)

type ProviderConfig struct {
	Name           string `toml:"name" json:"name"`
	ProviderType   string `toml:"provider_type,omitempty" json:"provider_type,omitempty"`
	BaseURL        string `toml:"base_url,omitempty" json:"base_url"`
	ModelListURL   string `toml:"model_list_url,omitempty" json:"model_list_url,omitempty"`
	APIKey         string `toml:"api_key,omitempty" json:"api_key,omitempty"`
	AuthToken      string `toml:"auth_token,omitempty" json:"auth_token,omitempty"`
	RefreshToken   string `toml:"refresh_token,omitempty" json:"refresh_token,omitempty"`
	TokenExpiresAt string `toml:"token_expires_at,omitempty" json:"token_expires_at,omitempty"`
	AccountID      string `toml:"account_id,omitempty" json:"account_id,omitempty"`
	DeviceAuthURL  string `toml:"device_auth_url,omitempty" json:"device_auth_url,omitempty"`
	Enabled        bool   `toml:"enabled,omitempty" json:"enabled,omitempty"`
	TimeoutSeconds int    `toml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
}

type TLSConfig struct {
	Enabled  bool   `toml:"enabled"`
	Domain   string `toml:"domain"`
	Email    string `toml:"email"`
	CacheDir string `toml:"cache_dir"`
}

type IncomingAPIToken struct {
	ID        string `toml:"id"`
	Name      string `toml:"name"`
	Role      string `toml:"role,omitempty"`
	ParentID  string `toml:"parent_id,omitempty"`
	Comment   string `toml:"comment,omitempty"`
	Key       string `toml:"key"`
	ExpiresAt string `toml:"expires_at,omitempty"`
	CreatedAt string `toml:"created_at,omitempty"`
}

type ServerConfig struct {
	ListenAddr                    string             `toml:"listen_addr"`
	IncomingTokens                []IncomingAPIToken `toml:"incoming_tokens"`
	AllowLocalhostNoAuth          bool               `toml:"allow_localhost_no_auth"`
	AllowHostDockerInternalNoAuth bool               `toml:"allow_host_docker_internal_no_auth"`
	AutoEnablePublicFreeModels    bool               `toml:"auto_enable_public_free_models"`
	DefaultProvider               string             `toml:"default_provider"`
	Providers                     []ProviderConfig   `toml:"providers"`
	TLS                           TLSConfig          `toml:"tls"`
}

type ClientConfig struct {
	ServerURL string `toml:"server_url"`
	APIKey    string `toml:"api_key,omitempty"`
}

func DefaultServerConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return defaultConfigFileName
	}
	return filepath.Join(home, ".config", "tokenrouter", defaultConfigFileName)
}

func DefaultClientConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "toro.toml"
	}
	return filepath.Join(home, ".config", "tokenrouter", "toro.toml")
}

func DefaultPricingCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "pricing-cache.json"
	}
	return filepath.Join(home, ".cache", "tokenrouter", "pricing-cache.json")
}

func DefaultUsageStatsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "usage-stats.json"
	}
	return filepath.Join(home, ".cache", "tokenrouter", "usage-stats.json")
}

func DefaultModelsCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "models-cache.json"
	}
	return filepath.Join(home, ".cache", "tokenrouter", "models-cache.json")
}

func NewDefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr:      ":8080",
		IncomingTokens:  []IncomingAPIToken{},
		DefaultProvider: "",
		Providers:       []ProviderConfig{},
		TLS: TLSConfig{
			Enabled:  false,
			Domain:   "",
			Email:    "",
			CacheDir: filepath.Join(os.TempDir(), "tokenrouter-autocert"),
		},
	}
}

func HasAdminToken(tokens []IncomingAPIToken) bool {
	now := time.Now().UTC()
	for _, t := range tokens {
		if NormalizeIncomingTokenRole(t.Role) != TokenRoleAdmin {
			continue
		}
		if strings.TrimSpace(t.Key) == "" {
			continue
		}
		if exp := strings.TrimSpace(t.ExpiresAt); exp != "" {
			ts, err := time.Parse(time.RFC3339, exp)
			if err != nil || !now.Before(ts) {
				continue
			}
		}
		return true
	}
	return false
}

func NewDefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		ServerURL: "http://127.0.0.1:8080/v1",
	}
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	cfg := NewDefaultClientConfig()
	if err := load(path, cfg); err != nil {
		return nil, err
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadOrCreateClientConfig(path string) (*ClientConfig, error) {
	cfg := NewDefaultClientConfig()
	if err := loadOrCreate(path, cfg); err != nil {
		return nil, err
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	cfg := NewDefaultServerConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := unmarshalServerConfigTOML(b, cfg); err != nil {
		return nil, err
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadOrCreateServerConfig(path string) (*ServerConfig, error) {
	cfg := NewDefaultServerConfig()
	if err := loadOrCreate(path, cfg); err != nil {
		return nil, err
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func loadOrCreate(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := writeAtomic(path, v); err != nil {
			return fmt.Errorf("write default config: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat config: %w", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if err := toml.Unmarshal(b, v); err != nil {
		return fmt.Errorf("parse toml: %w", err)
	}
	return nil
}

func load(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if err := toml.Unmarshal(b, v); err != nil {
		return fmt.Errorf("parse toml: %w", err)
	}
	return nil
}

func unmarshalServerConfigTOML(b []byte, cfg *ServerConfig) error {
	type legacyServerConfig struct {
		ServerConfig
		IncomingAPIKeys []string `toml:"incoming_api_keys"`
		AdminAPIKey     string   `toml:"admin_api_key"`
	}
	var raw legacyServerConfig
	if err := toml.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("parse toml: %w", err)
	}
	*cfg = raw.ServerConfig
	if len(cfg.IncomingTokens) == 0 && len(raw.IncomingAPIKeys) > 0 {
		cfg.IncomingTokens = make([]IncomingAPIToken, 0, len(raw.IncomingAPIKeys))
		for i, k := range raw.IncomingAPIKeys {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			cfg.IncomingTokens = append(cfg.IncomingTokens, IncomingAPIToken{
				ID:   tokenID(k, i),
				Name: fmt.Sprintf("Token %d", len(cfg.IncomingTokens)+1),
				Role: TokenRoleInferrer,
				Key:  k,
			})
		}
	}
	legacyAdminKey := strings.TrimSpace(raw.AdminAPIKey)
	if legacyAdminKey != "" {
		matched := false
		for i := range cfg.IncomingTokens {
			if strings.TrimSpace(cfg.IncomingTokens[i].Key) != legacyAdminKey {
				continue
			}
			cfg.IncomingTokens[i].Role = TokenRoleAdmin
			if strings.TrimSpace(cfg.IncomingTokens[i].Name) == "" {
				cfg.IncomingTokens[i].Name = "Admin"
			}
			matched = true
		}
		if !matched {
			cfg.IncomingTokens = append(cfg.IncomingTokens, IncomingAPIToken{
				ID:   tokenID(legacyAdminKey, len(cfg.IncomingTokens)),
				Name: "Admin",
				Role: TokenRoleAdmin,
				Key:  legacyAdminKey,
			})
		}
	}
	return nil
}

func Save(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	return writeAtomic(path, v)
}

func writeAtomic(path string, v any) error {
	b, err := marshalTOML(v)
	if err != nil {
		return fmt.Errorf("encode toml: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func marshalTOML(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := toml.NewEncoder(&buf)
	enc.SetArraysMultiline(true)
	enc.SetIndentSymbol("  ")
	enc.SetIndentTables(true)
	enc.SetTablesInline(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return out, nil
}

func (c *ServerConfig) Normalize() {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}
	if c.TLS.CacheDir == "" {
		c.TLS.CacheDir = filepath.Join(os.TempDir(), "tokenrouter-autocert")
	}
	tokenSeen := map[string]struct{}{}
	tokens := make([]IncomingAPIToken, 0, len(c.IncomingTokens))
	for i, t := range c.IncomingTokens {
		t.ID = strings.TrimSpace(t.ID)
		t.Name = strings.TrimSpace(t.Name)
		t.Role = NormalizeIncomingTokenRole(t.Role)
		t.ParentID = strings.TrimSpace(t.ParentID)
		t.Comment = strings.TrimSpace(t.Comment)
		t.Key = strings.TrimSpace(t.Key)
		t.ExpiresAt = strings.TrimSpace(t.ExpiresAt)
		t.CreatedAt = strings.TrimSpace(t.CreatedAt)
		if t.Key == "" {
			continue
		}
		if _, ok := tokenSeen[t.Key]; ok {
			continue
		}
		tokenSeen[t.Key] = struct{}{}
		if t.ID == "" {
			t.ID = tokenID(t.Key, i)
		}
		if t.Name == "" {
			t.Name = fmt.Sprintf("Token %d", len(tokens)+1)
		}
		tokens = append(tokens, t)
	}
	c.IncomingTokens = tokens
	for i := range c.Providers {
		c.Providers[i].Name = strings.TrimSpace(c.Providers[i].Name)
		c.Providers[i].ProviderType = strings.TrimSpace(c.Providers[i].ProviderType)
		c.Providers[i].BaseURL = strings.TrimSpace(c.Providers[i].BaseURL)
		c.Providers[i].APIKey = strings.TrimSpace(c.Providers[i].APIKey)
		c.Providers[i].AuthToken = strings.TrimSpace(c.Providers[i].AuthToken)
		c.Providers[i].RefreshToken = strings.TrimSpace(c.Providers[i].RefreshToken)
		c.Providers[i].TokenExpiresAt = strings.TrimSpace(c.Providers[i].TokenExpiresAt)
		c.Providers[i].AccountID = strings.TrimSpace(c.Providers[i].AccountID)
		c.Providers[i].DeviceAuthURL = strings.TrimSpace(c.Providers[i].DeviceAuthURL)
		if c.Providers[i].ProviderType == "" {
			c.Providers[i].ProviderType = c.Providers[i].Name
		}
	}

	sort.SliceStable(c.Providers, func(i, j int) bool { return c.Providers[i].Name < c.Providers[j].Name })
}

func (c *ServerConfig) Validate() error {
	idSeen := map[string]struct{}{}
	for _, t := range c.IncomingTokens {
		if t.ID == "" {
			return errors.New("incoming token id cannot be empty")
		}
		if _, ok := idSeen[t.ID]; ok {
			return fmt.Errorf("duplicate incoming token id %q", t.ID)
		}
		idSeen[t.ID] = struct{}{}
		if t.Name == "" {
			return fmt.Errorf("incoming token %q name cannot be empty", t.ID)
		}
		t.Role = NormalizeIncomingTokenRole(t.Role)
		if t.Role == "" {
			return fmt.Errorf("incoming token %q has invalid role", t.ID)
		}
		if t.Key == "" {
			return fmt.Errorf("incoming token %q key cannot be empty", t.ID)
		}
		if t.ExpiresAt != "" {
			if _, err := time.Parse(time.RFC3339, t.ExpiresAt); err != nil {
				return fmt.Errorf("incoming token %q has invalid expires_at (RFC3339 required)", t.ID)
			}
		}
		if t.CreatedAt != "" {
			if _, err := time.Parse(time.RFC3339, t.CreatedAt); err != nil {
				return fmt.Errorf("incoming token %q has invalid created_at (RFC3339 required)", t.ID)
			}
		}
	}
	if c.TLS.Enabled && c.TLS.Domain == "" {
		return errors.New("tls.domain is required when tls.enabled=true")
	}
	nameSeen := map[string]struct{}{}
	for _, p := range c.Providers {
		if p.Name == "" {
			return errors.New("provider name cannot be empty")
		}
		if _, ok := nameSeen[p.Name]; ok {
			return fmt.Errorf("duplicate provider name %q", p.Name)
		}
		nameSeen[p.Name] = struct{}{}
	}
	if c.DefaultProvider != "" {
		if _, ok := nameSeen[c.DefaultProvider]; !ok {
			return fmt.Errorf("default_provider %q not found", c.DefaultProvider)
		}
	}
	return nil
}

func (c *ClientConfig) Normalize() {
	c.ServerURL = strings.TrimSpace(c.ServerURL)
	c.APIKey = strings.TrimSpace(c.APIKey)
	if c.ServerURL == "" {
		c.ServerURL = "http://127.0.0.1:8080/v1"
	}
}

func (c *ClientConfig) Validate() error {
	if strings.TrimSpace(c.ServerURL) == "" {
		return errors.New("server_url cannot be empty")
	}
	return nil
}

type ServerConfigStore struct {
	mu   sync.RWMutex
	path string
	cfg  *ServerConfig
}

func NewServerConfigStore(path string, cfg *ServerConfig) *ServerConfigStore {
	return &ServerConfigStore{path: path, cfg: cfg}
}

func (s *ServerConfigStore) Snapshot() ServerConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := *s.cfg
	cp.IncomingTokens = append([]IncomingAPIToken(nil), s.cfg.IncomingTokens...)
	cp.Providers = append([]ProviderConfig(nil), s.cfg.Providers...)
	return cp
}

func (s *ServerConfigStore) Update(mutator func(*ServerConfig) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *s.cfg
	cp.IncomingTokens = append([]IncomingAPIToken(nil), s.cfg.IncomingTokens...)
	cp.Providers = append([]ProviderConfig(nil), s.cfg.Providers...)
	if err := mutator(&cp); err != nil {
		return err
	}
	cp.Normalize()
	if err := cp.Validate(); err != nil {
		return err
	}
	if err := Save(s.path, &cp); err != nil {
		return err
	}
	s.cfg = &cp
	return nil
}

func tokenID(key string, idx int) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(key))
	return fmt.Sprintf("tok-%d-%x", idx+1, h.Sum64())
}

func NormalizeIncomingTokenRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "", TokenRoleInferrer:
		return TokenRoleInferrer
	case TokenRoleAdmin:
		return TokenRoleAdmin
	case TokenRoleKeymaster:
		return TokenRoleKeymaster
	default:
		return ""
	}
}
