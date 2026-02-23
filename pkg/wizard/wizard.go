package wizard

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/lkarlslund/openai-personal-proxy/pkg/config"
)

func RunServerWizard(path string, cfg *config.ServerConfig) error {
	in := bufio.NewScanner(os.Stdin)
	fmt.Println("Server configuration wizard")
	cfg.ListenAddr = ask(in, "Public listen address", cfg.ListenAddr)
	keys := ask(in, "Incoming API keys (comma-separated)", strings.Join(cfg.IncomingAPIKeys, ","))
	cfg.IncomingAPIKeys = splitCSV(keys)
	cfg.AdminAPIKey = ask(in, "Admin API key", cfg.AdminAPIKey)
	cfg.DefaultProvider = ask(in, "Default provider name", cfg.DefaultProvider)

	tlsEnabled := ask(in, "Enable Let's Encrypt TLS? (y/N)", boolStr(cfg.TLS.Enabled))
	cfg.TLS.Enabled = strings.EqualFold(strings.TrimSpace(tlsEnabled), "y") || strings.EqualFold(strings.TrimSpace(tlsEnabled), "yes") || strings.EqualFold(strings.TrimSpace(tlsEnabled), "true")
	if cfg.TLS.Enabled {
		cfg.TLS.Domain = ask(in, "TLS domain", cfg.TLS.Domain)
		cfg.TLS.Email = ask(in, "ACME email", cfg.TLS.Email)
		cfg.TLS.CacheDir = ask(in, "ACME cache dir", cfg.TLS.CacheDir)
	}

	providerCountStr := ask(in, "Number of providers to configure", strconv.Itoa(len(cfg.Providers)))
	providerCount, _ := strconv.Atoi(strings.TrimSpace(providerCountStr))
	if providerCount < 0 {
		providerCount = 0
	}
	providers := make([]config.ProviderConfig, 0, providerCount)
	for i := 0; i < providerCount; i++ {
		fmt.Printf("Provider %d\n", i+1)
		p := config.ProviderConfig{Enabled: true, TimeoutSeconds: 60}
		if i < len(cfg.Providers) {
			p = cfg.Providers[i]
		}
		p.Name = ask(in, "  name", p.Name)
		p.BaseURL = ask(in, "  base_url", p.BaseURL)
		p.APIKey = ask(in, "  api_key", p.APIKey)
		enabled := ask(in, "  enabled (true/false)", boolStr(p.Enabled))
		p.Enabled = strings.EqualFold(strings.TrimSpace(enabled), "true") || strings.EqualFold(strings.TrimSpace(enabled), "y") || strings.EqualFold(strings.TrimSpace(enabled), "yes")
		tout := ask(in, "  timeout_seconds", strconv.Itoa(p.TimeoutSeconds))
		if v, err := strconv.Atoi(strings.TrimSpace(tout)); err == nil && v > 0 {
			p.TimeoutSeconds = v
		}
		providers = append(providers, p)
	}
	cfg.Providers = providers
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return err
	}
	return config.Save(path, cfg)
}

func ask(in *bufio.Scanner, label, def string) string {
	if def == "" {
		fmt.Printf("%s: ", label)
	} else {
		fmt.Printf("%s [%s]: ", label, def)
	}
	if !in.Scan() {
		return def
	}
	txt := strings.TrimSpace(in.Text())
	if txt == "" {
		return def
	}
	return txt
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
