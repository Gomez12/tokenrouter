package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/tokenrouter/pkg/config"
	"github.com/lkarlslund/tokenrouter/pkg/logutil"
	"github.com/lkarlslund/tokenrouter/pkg/version"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
)

func main() {
	var wrapperTokenName string
	var wrapperTTL time.Duration
	root := &cobra.Command{
		Use:   "toro",
		Short: "TokenRouter client CLI",
		Long:  "Toro is the TokenRouter client CLI. It will later support wrapping other programs.",
	}
	root.SilenceUsage = true
	root.SilenceErrors = true
	var logLevel string
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return logutil.Configure(logLevel)
	}
	root.PersistentFlags().StringVar(&logLevel, "loglevel", "info", "Log level (trace, debug, info, warn, error, fatal)")
	root.PersistentFlags().StringVar(&wrapperTokenName, "name", "", "Temporary token display name for wrapper commands (codex, opencode, wrap)")
	root.PersistentFlags().DurationVar(&wrapperTTL, "ttl", 8*time.Hour, "Temporary token expiry duration for wrapper commands (codex, opencode, wrap)")

	var clientConfigPath string
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Configure remote TokenRouter server URL and API key",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConnectTUI(cmd, clientConfigPath, "")
		},
	}
	configCmd.Flags().StringVar(&clientConfigPath, "config", config.DefaultClientConfigPath(), "Client config TOML path")
	root.AddCommand(configCmd)

	var connectConfigPath string
	var connectServerConfigPath string
	connectCmd := &cobra.Command{
		Use:   "connect",
		Short: "Connect toro to a TokenRouter server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConnectTUI(cmd, connectConfigPath, connectServerConfigPath)
		},
	}
	connectCmd.Flags().StringVar(&connectConfigPath, "config", config.DefaultClientConfigPath(), "Client config TOML path")
	connectCmd.Flags().StringVar(&connectServerConfigPath, "server-config", "", "Server config TOML path to read defaults from (also checks common paths)")
	root.AddCommand(connectCmd)
	setKeyCmd := &cobra.Command{
		Use:   "set-key <api_key>",
		Short: "Set and save client API key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetKey(cmd, clientConfigPath, args[0])
		},
	}
	setKeyCmd.Flags().StringVar(&clientConfigPath, "config", config.DefaultClientConfigPath(), "Client config TOML path")
	root.AddCommand(setKeyCmd)

	var statusConfigPath string
	var statusAsJSON bool
	var statusPeriodSeconds int
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show TokenRouter server health, version, and provider quotas",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(cmd, statusConfigPath, statusAsJSON, statusPeriodSeconds)
		},
	}
	statusCmd.Flags().StringVar(&statusConfigPath, "config", config.DefaultClientConfigPath(), "Client config TOML path")
	statusCmd.Flags().BoolVar(&statusAsJSON, "json", false, "Output status as JSON")
	statusCmd.Flags().IntVar(&statusPeriodSeconds, "period-seconds", 3600, "Usage/quota lookback period in seconds")
	root.AddCommand(statusCmd)

	var opencodeConfigPath string
	var opencodeProviderID string
	var opencodeProviderName string
	var opencodeModel string
	var opencodeDisableOtherProviders bool
	opencodeCmd := &cobra.Command{
		Use:   "opencode [wrapper_flags] [opencode_args...]",
		Short: "Launch opencode with a temporary subordinate TokenRouter key",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOpencodeWrap(cmd, opencodeConfigPath, wrapperTokenName, opencodeProviderID, opencodeProviderName, opencodeModel, wrapperTTL, opencodeDisableOtherProviders, args)
		},
	}
	opencodeCmd.FParseErrWhitelist.UnknownFlags = true
	opencodeCmd.Flags().SetInterspersed(false)
	opencodeCmd.Flags().StringVar(&opencodeConfigPath, "config", config.DefaultClientConfigPath(), "Client config TOML path")
	opencodeCmd.Flags().StringVar(&opencodeProviderID, "provider-id", "tokenrouter", "Injected opencode provider id")
	opencodeCmd.Flags().StringVar(&opencodeProviderName, "provider-name", "TokenRouter", "Injected opencode provider display name")
	opencodeCmd.Flags().StringVar(&opencodeModel, "model", "", "Optional model to select (bare model id or provider/model)")
	opencodeCmd.Flags().BoolVar(&opencodeDisableOtherProviders, "disable-other-providers", true, "Disable all other opencode providers while wrapped")
	root.AddCommand(opencodeCmd)

	var codexConfigPath string
	var codexModel string
	codexCmd := &cobra.Command{
		Use:   "codex [wrapper_flags] [codex_args...]",
		Short: "Launch codex-cli with a temporary subordinate TokenRouter key",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCodexWrap(cmd, codexConfigPath, wrapperTokenName, codexModel, wrapperTTL, args)
		},
	}
	codexCmd.FParseErrWhitelist.UnknownFlags = true
	codexCmd.Flags().SetInterspersed(false)
	codexCmd.Flags().StringVar(&codexConfigPath, "config", config.DefaultClientConfigPath(), "Client config TOML path")
	codexCmd.Flags().StringVar(&codexModel, "model", "", "Optional model override passed via OPENAI_MODEL")
	root.AddCommand(codexCmd)

	var wrapConfigPath string
	var wrapURLEnv string
	var wrapKeyEnv string
	wrapCmd := &cobra.Command{
		Use:   "wrap [wrapper_flags] <command> [args...]",
		Short: "Run any command with a temporary subordinate TokenRouter key",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenericWrap(cmd, wrapConfigPath, wrapperTokenName, wrapperTTL, wrapURLEnv, wrapKeyEnv, args)
		},
	}
	wrapCmd.Flags().SetInterspersed(false)
	wrapCmd.Flags().StringVar(&wrapConfigPath, "config", config.DefaultClientConfigPath(), "Client config TOML path")
	wrapCmd.Flags().StringVar(&wrapURLEnv, "url-env", "OPENAI_BASE_URL", "Environment variable name for TokenRouter /v1 URL")
	wrapCmd.Flags().StringVar(&wrapKeyEnv, "key-env", "OPENAI_API_KEY", "Environment variable name for API key")
	root.AddCommand(wrapCmd)

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print toro version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version.Detailed("toro"))
		},
	})

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runConfigTUI(cmd *cobra.Command, path string) error {
	return runConnectTUI(cmd, path, "")
}

func runConnectTUI(cmd *cobra.Command, path, explicitServerConfigPath string) error {
	cfg, err := config.LoadOrCreateClientConfig(path)
	if err != nil {
		return fmt.Errorf("load client config: %w", err)
	}
	reader := bufio.NewReader(cmd.InOrStdin())
	out := cmd.OutOrStdout()
	hints := discoverServerConnectHints(explicitServerConfigPath)

	fmt.Fprintf(out, "Toro connect\nClient config: %s\n", path)
	if strings.TrimSpace(hints.SourcePath) != "" {
		fmt.Fprintf(out, "Using defaults from server config: %s\n", hints.SourcePath)
	}
	fmt.Fprintln(out, "Press Enter to keep current/default value.")
	fmt.Fprintln(out, "Enter '-' for API key to clear it.")

	defaultURL := strings.TrimSpace(cfg.ServerURL)
	if defaultURL == "" || defaultURL == config.NewDefaultClientConfig().ServerURL {
		if strings.TrimSpace(hints.ServerURL) != "" {
			defaultURL = strings.TrimSpace(hints.ServerURL)
		} else {
			defaultURL = "http://localhost:8080"
		}
	}

	serverURL, err := promptLine(reader, out, fmt.Sprintf("Remote server URL [%s]: ", defaultURL))
	if err != nil {
		return err
	}
	serverURL = strings.TrimSpace(serverURL)
	if serverURL == "" {
		cfg.ServerURL = defaultURL
	} else {
		cfg.ServerURL = strings.TrimSpace(serverURL)
	}

	apiKeyPrompt := "API key [not set]: "
	defaultKey := strings.TrimSpace(cfg.APIKey)
	if defaultKey == "" {
		defaultKey = strings.TrimSpace(hints.APIKey)
	}
	if defaultKey != "" {
		redacted := defaultKey
		if len(redacted) <= 4 {
			redacted = strings.Repeat("*", len(redacted))
		} else {
			redacted = redacted[:4] + strings.Repeat("*", len(redacted)-4)
		}
		apiKeyPrompt = fmt.Sprintf("API key [%s]: ", redacted)
	}
	apiKeyInput, err := promptLine(reader, out, apiKeyPrompt)
	if err != nil {
		return err
	}
	apiKeyInput = strings.TrimSpace(apiKeyInput)
	switch apiKeyInput {
	case "":
		cfg.APIKey = defaultKey
	case "-":
		cfg.APIKey = ""
	default:
		cfg.APIKey = apiKeyInput
	}

	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := config.Save(path, cfg); err != nil {
		return fmt.Errorf("save client config: %w", err)
	}
	fmt.Fprintln(out, "Saved.")
	return nil
}

type connectHints struct {
	SourcePath string
	ServerURL  string
	APIKey     string
}

func discoverServerConnectHints(explicitPath string) connectHints {
	seen := map[string]struct{}{}
	paths := make([]string, 0, 4)
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		paths = append(paths, p)
	}
	add(explicitPath)
	add(config.DefaultServerConfigPath())
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		add(filepath.Join(home, ".config", "tokenrouter", "server.toml"))
	}
	add("server.toml")

	for _, path := range paths {
		h, err := readServerConnectHints(path)
		if err != nil {
			continue
		}
		if strings.TrimSpace(h.ServerURL) == "" && strings.TrimSpace(h.APIKey) == "" {
			continue
		}
		h.SourcePath = path
		return h
	}
	return connectHints{}
}

func readServerConnectHints(path string) (connectHints, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return connectHints{}, err
	}
	var raw struct {
		ListenAddr string `toml:"listen_addr"`
		TLS        struct {
			Enabled    bool   `toml:"enabled"`
			ListenAddr string `toml:"listen_addr"`
		} `toml:"tls"`
		IncomingTokens []struct {
			Role      string `toml:"role"`
			Key       string `toml:"key"`
			ExpiresAt string `toml:"expires_at"`
		} `toml:"incoming_tokens"`
	}
	if err := toml.Unmarshal(b, &raw); err != nil {
		return connectHints{}, err
	}
	return connectHints{
		ServerURL: connectURLFromServerConfig(raw.ListenAddr, raw.TLS.Enabled, raw.TLS.ListenAddr),
		APIKey:    bestTokenKey(raw.IncomingTokens),
	}, nil
}

func connectURLFromServerConfig(httpListen string, tlsEnabled bool, tlsListen string) string {
	scheme := "http"
	addr := strings.TrimSpace(httpListen)
	defaultPort := "8080"
	if tlsEnabled {
		scheme = "https"
		if strings.TrimSpace(tlsListen) != "" {
			addr = strings.TrimSpace(tlsListen)
		}
		defaultPort = "443"
	}
	host, port := connectHostPort(addr)
	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = defaultPort
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host + ":" + port
}

func connectHostPort(addr string) (string, string) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "localhost", ""
	}
	if strings.Contains(addr, "://") {
		if u, err := neturl.Parse(addr); err == nil {
			return connectHostPort(u.Host)
		}
	}
	if strings.HasPrefix(addr, ":") {
		return "localhost", strings.TrimPrefix(addr, ":")
	}
	if host, port, err := net.SplitHostPort(addr); err == nil {
		return normalizeConnectHost(host), strings.TrimSpace(port)
	}
	// Fallback for simple host or host:port without strict net.SplitHostPort support.
	if strings.Count(addr, ":") == 1 {
		parts := strings.SplitN(addr, ":", 2)
		return normalizeConnectHost(parts[0]), strings.TrimSpace(parts[1])
	}
	return normalizeConnectHost(addr), ""
}

func normalizeConnectHost(host string) string {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	switch strings.ToLower(host) {
	case "", "0.0.0.0", "::", "::0", "*":
		return "localhost"
	default:
		return host
	}
}

func bestTokenKey(tokens []struct {
	Role      string `toml:"role"`
	Key       string `toml:"key"`
	ExpiresAt string `toml:"expires_at"`
}) string {
	now := time.Now().UTC()
	bestPriority := 99
	best := ""
	for _, t := range tokens {
		key := strings.TrimSpace(t.Key)
		if key == "" {
			continue
		}
		exp := strings.TrimSpace(t.ExpiresAt)
		if exp != "" {
			ts, err := time.Parse(time.RFC3339, exp)
			if err == nil && !now.Before(ts) {
				continue
			}
		}
		p := rolePriority(strings.TrimSpace(t.Role))
		if p < bestPriority {
			bestPriority = p
			best = key
		}
	}
	return best
}

func rolePriority(role string) int {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin":
		return 0
	case "keymaster":
		return 1
	case "", "inferrer":
		return 2
	default:
		return 3
	}
}

func runSetKey(cmd *cobra.Command, path, apiKey string) error {
	cfg, err := config.LoadOrCreateClientConfig(path)
	if err != nil {
		return fmt.Errorf("load client config: %w", err)
	}
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return fmt.Errorf("api key cannot be empty")
	}
	cfg.APIKey = apiKey
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := config.Save(path, cfg); err != nil {
		return fmt.Errorf("save client config: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Saved key.")
	return nil
}

type statusHealth struct {
	OK         bool   `json:"ok"`
	StatusCode int    `json:"status_code,omitempty"`
	Body       string `json:"body,omitempty"`
	Error      string `json:"error,omitempty"`
}

type statusVersion struct {
	Version string `json:"version,omitempty"`
	Raw     string `json:"raw,omitempty"`
	Commit  string `json:"commit,omitempty"`
	Date    string `json:"date,omitempty"`
	Dirty   bool   `json:"dirty,omitempty"`
	Error   string `json:"error,omitempty"`
}

type statusQuotaMetric struct {
	Key            string  `json:"key,omitempty"`
	MeteredFeature string  `json:"metered_feature,omitempty"`
	Window         string  `json:"window,omitempty"`
	LeftPercent    float64 `json:"left_percent,omitempty"`
	ResetAt        string  `json:"reset_at,omitempty"`
	Unit           string  `json:"unit,omitempty"`
}

type statusProviderQuota struct {
	Provider    string              `json:"provider"`
	Status      string              `json:"status,omitempty"`
	PlanType    string              `json:"plan_type,omitempty"`
	LeftPercent float64             `json:"left_percent,omitempty"`
	ResetAt     string              `json:"reset_at,omitempty"`
	Error       string              `json:"error,omitempty"`
	Metrics     []statusQuotaMetric `json:"metrics,omitempty"`
}

type statusStats struct {
	ProvidersAvailable int                   `json:"providers_available,omitempty"`
	ProvidersOnline    int                   `json:"providers_online,omitempty"`
	ProviderQuotas     []statusProviderQuota `json:"provider_quotas,omitempty"`
	Error              string                `json:"error,omitempty"`
}

type statusReport struct {
	CheckedAt string        `json:"checked_at"`
	ServerURL string        `json:"server_url"`
	Health    statusHealth  `json:"health"`
	Version   statusVersion `json:"version"`
	Stats     statusStats   `json:"stats"`
}

func runStatus(cmd *cobra.Command, cfgPath string, asJSON bool, periodSeconds int) error {
	cfg, err := config.LoadClientConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load client config (run `toro connect` first): %w", err)
	}
	serverBase, err := deriveServerBaseURL(cfg.ServerURL)
	if err != nil {
		return err
	}
	if periodSeconds <= 0 {
		periodSeconds = 3600
	}

	report := statusReport{
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
		ServerURL: strings.TrimSuffix(serverBase, "/") + "/v1",
	}

	report.Health = checkServerHealth(serverBase)

	if strings.TrimSpace(cfg.APIKey) == "" {
		report.Version.Error = "api key not configured in toro client config"
		report.Stats.Error = "api key not configured in toro client config"
	} else {
		v, s := readServerStatus(serverBase, cfg.APIKey, periodSeconds)
		report.Version = v
		report.Stats = s
	}

	if asJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	printStatusReportHuman(cmd.OutOrStdout(), report)
	return nil
}

func checkServerHealth(serverBase string) statusHealth {
	u := strings.TrimSuffix(serverBase, "/") + "/healthz"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return statusHealth{Error: err.Error()}
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return statusHealth{Error: err.Error()}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	body := strings.TrimSpace(string(b))
	return statusHealth{
		OK:         resp.StatusCode == http.StatusOK,
		StatusCode: resp.StatusCode,
		Body:       body,
	}
}

func readServerStatus(serverBase, apiKey string, periodSeconds int) (statusVersion, statusStats) {
	path := "/v1/status?period_seconds=" + strconv.Itoa(periodSeconds)
	req, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(serverBase, "/")+path, nil)
	if err != nil {
		msg := err.Error()
		return statusVersion{Error: msg}, statusStats{Error: msg}
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(apiKey))
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		msg := err.Error()
		return statusVersion{Error: msg}, statusStats{Error: msg}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		msg := fmt.Sprintf("status endpoint error (%d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
		return statusVersion{Error: msg}, statusStats{Error: msg}
	}

	var raw struct {
		Version string `json:"version"`
		Raw     string `json:"raw"`
		Commit  string `json:"commit"`
		Date    string `json:"date"`
		Dirty   bool   `json:"dirty"`

		ProvidersAvailable int `json:"providers_available"`
		ProvidersOnline    int `json:"providers_online"`
		ProviderQuotas     map[string]struct {
			Provider    string  `json:"provider"`
			Status      string  `json:"status"`
			PlanType    string  `json:"plan_type"`
			LeftPercent float64 `json:"left_percent"`
			ResetAt     string  `json:"reset_at"`
			Error       string  `json:"error"`
			Metrics     []struct {
				Key            string  `json:"key"`
				MeteredFeature string  `json:"metered_feature"`
				Window         string  `json:"window"`
				LeftPercent    float64 `json:"left_percent"`
				ResetAt        string  `json:"reset_at"`
				Unit           string  `json:"unit"`
			} `json:"metrics"`
		} `json:"provider_quotas"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		msg := err.Error()
		return statusVersion{Error: msg}, statusStats{Error: msg}
	}

	version := statusVersion{
		Version: strings.TrimSpace(raw.Version),
		Raw:     strings.TrimSpace(raw.Raw),
		Commit:  strings.TrimSpace(raw.Commit),
		Date:    strings.TrimSpace(raw.Date),
		Dirty:   raw.Dirty,
	}
	stats := statusStats{
		ProvidersAvailable: raw.ProvidersAvailable,
		ProvidersOnline:    raw.ProvidersOnline,
		ProviderQuotas:     make([]statusProviderQuota, 0, len(raw.ProviderQuotas)),
	}
	for providerName, q := range raw.ProviderQuotas {
		item := statusProviderQuota{
			Provider:    strings.TrimSpace(providerName),
			Status:      strings.TrimSpace(q.Status),
			PlanType:    strings.TrimSpace(q.PlanType),
			LeftPercent: q.LeftPercent,
			ResetAt:     strings.TrimSpace(q.ResetAt),
			Error:       strings.TrimSpace(q.Error),
			Metrics:     make([]statusQuotaMetric, 0, len(q.Metrics)),
		}
		if strings.TrimSpace(q.Provider) != "" {
			item.Provider = strings.TrimSpace(q.Provider)
		}
		for _, m := range q.Metrics {
			item.Metrics = append(item.Metrics, statusQuotaMetric{
				Key:            strings.TrimSpace(m.Key),
				MeteredFeature: strings.TrimSpace(m.MeteredFeature),
				Window:         strings.TrimSpace(m.Window),
				LeftPercent:    m.LeftPercent,
				ResetAt:        strings.TrimSpace(m.ResetAt),
				Unit:           strings.TrimSpace(m.Unit),
			})
		}
		sort.Slice(item.Metrics, func(i, j int) bool {
			if item.Metrics[i].MeteredFeature == item.Metrics[j].MeteredFeature {
				return item.Metrics[i].Window < item.Metrics[j].Window
			}
			return item.Metrics[i].MeteredFeature < item.Metrics[j].MeteredFeature
		})
		stats.ProviderQuotas = append(stats.ProviderQuotas, item)
	}
	sort.Slice(stats.ProviderQuotas, func(i, j int) bool {
		return stats.ProviderQuotas[i].Provider < stats.ProviderQuotas[j].Provider
	})
	return version, stats
}

func printStatusReportHuman(w io.Writer, report statusReport) {
	healthText := "down"
	if report.Health.OK {
		healthText = "ok"
	}
	fmt.Fprintf(w, "Server: %s\n", report.ServerURL)
	fmt.Fprintf(w, "Checked: %s\n", report.CheckedAt)
	if strings.TrimSpace(report.Health.Error) != "" {
		fmt.Fprintf(w, "Health: %s (%s)\n", healthText, report.Health.Error)
	} else {
		body := strings.TrimSpace(report.Health.Body)
		if body != "" {
			fmt.Fprintf(w, "Health: %s (status=%d, body=%q)\n", healthText, report.Health.StatusCode, body)
		} else {
			fmt.Fprintf(w, "Health: %s (status=%d)\n", healthText, report.Health.StatusCode)
		}
	}

	if strings.TrimSpace(report.Version.Error) != "" {
		fmt.Fprintf(w, "Version: unavailable (%s)\n", report.Version.Error)
	} else {
		version := strings.TrimSpace(report.Version.Version)
		if version == "" {
			version = "unknown"
		}
		if strings.TrimSpace(report.Version.Commit) != "" {
			commit := report.Version.Commit
			if len(commit) > 12 {
				commit = commit[:12]
			}
			fmt.Fprintf(w, "Version: %s (commit=%s)\n", version, commit)
		} else {
			fmt.Fprintf(w, "Version: %s\n", version)
		}
	}

	if strings.TrimSpace(report.Stats.Error) != "" {
		fmt.Fprintf(w, "Providers: unavailable (%s)\n", report.Stats.Error)
		fmt.Fprintln(w, "Quota: unavailable")
		return
	}

	fmt.Fprintf(w, "Providers: %d online / %d available\n", report.Stats.ProvidersOnline, report.Stats.ProvidersAvailable)
	if len(report.Stats.ProviderQuotas) == 0 {
		fmt.Fprintln(w, "Quota: no data")
		return
	}
	fmt.Fprintln(w, "Quota:")
	for _, p := range report.Stats.ProviderQuotas {
		status := strings.TrimSpace(p.Status)
		if status == "" {
			status = "unknown"
		}
		line := fmt.Sprintf("  - %s: status=%s", p.Provider, status)
		if p.LeftPercent > 0 {
			line += fmt.Sprintf(", left=%.1f%%", p.LeftPercent)
		}
		if strings.TrimSpace(p.ResetAt) != "" {
			line += ", reset=" + p.ResetAt
		}
		if strings.TrimSpace(p.Error) != "" {
			line += ", error=" + p.Error
		}
		fmt.Fprintln(w, line)
		if len(p.Metrics) > 0 {
			for _, m := range p.Metrics {
				label := strings.TrimSpace(m.MeteredFeature)
				if label == "" {
					label = "quota"
				}
				if strings.TrimSpace(m.Window) != "" {
					label += "/" + m.Window
				}
				sub := fmt.Sprintf("      * %s: %.1f%% left", label, m.LeftPercent)
				if strings.TrimSpace(m.ResetAt) != "" {
					sub += ", reset=" + m.ResetAt
				}
				fmt.Fprintln(w, sub)
			}
		}
	}
}

func promptLine(reader *bufio.Reader, out io.Writer, prompt string) (string, error) {
	fmt.Fprint(out, prompt)
	line, err := reader.ReadString('\n')
	if err != nil {
		if len(line) == 0 {
			return "", err
		}
	}
	return strings.TrimRight(line, "\r\n"), nil
}

type accessTokenItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Role        string `json:"role,omitempty"`
	RedactedKey string `json:"redacted_key"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

func runOpencodeWrap(cmd *cobra.Command, cfgPath, tokenName, providerID, providerName, model string, ttl time.Duration, disableOtherProviders bool, opencodeArgs []string) error {
	cfg, err := config.LoadClientConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load client config (run `toro config` first): %w", err)
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return fmt.Errorf("client api key is required (set with: toro config)")
	}
	serverBase, err := deriveServerBaseURL(cfg.ServerURL)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		return fmt.Errorf("ttl must be > 0")
	}
	providerID = strings.TrimSpace(providerID)
	if providerID == "" {
		return fmt.Errorf("provider-id cannot be empty")
	}
	providerName = strings.TrimSpace(providerName)
	if providerName == "" {
		providerName = "TokenRouter"
	}
	key, err := randomTemporaryKey()
	if err != nil {
		return fmt.Errorf("generate temporary key: %w", err)
	}
	if strings.TrimSpace(tokenName) == "" {
		tokenName = "toro-opencode-" + time.Now().UTC().Format("20060102-150405")
	}
	expiresAt := time.Now().UTC().Add(ttl).Format(time.RFC3339)

	before, err := fetchAccessTokens(serverBase, cfg.APIKey)
	if err != nil {
		return fmt.Errorf("list access tokens before create: %w", err)
	}
	beforeIDs := map[string]struct{}{}
	for _, t := range before {
		beforeIDs[strings.TrimSpace(t.ID)] = struct{}{}
	}
	if err := createAccessToken(serverBase, cfg.APIKey, tokenName, key, "inferrer", expiresAt); err != nil {
		return fmt.Errorf("create temporary access token: %w", err)
	}
	tmpID, err := findCreatedTokenID(serverBase, cfg.APIKey, beforeIDs, tokenName, expiresAt)
	if err != nil {
		return fmt.Errorf("locate temporary access token id: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Created temporary token %q (id=%s, expires=%s)\n", tokenName, tmpID, expiresAt)

	cleanup := func() {
		if err := deleteAccessToken(serverBase, cfg.APIKey, tmpID); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: failed to delete temporary token %q (id=%s): %v\n", tokenName, tmpID, err)
			return
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Deleted temporary token %q (id=%s)\n", tokenName, tmpID)
	}
	defer cleanup()

	configContent, err := buildOpencodeConfigContent(serverBase, key, providerID, providerName, model)
	if err != nil {
		return err
	}
	proc := exec.Command("opencode", opencodeArgs...)
	proc.Stdin = cmd.InOrStdin()
	proc.Stdout = cmd.OutOrStdout()
	proc.Stderr = cmd.ErrOrStderr()
	env := filteredEnv([]string{"OPENCODE_CONFIG", "OPENCODE_CONFIG_CONTENT"})
	if disableOtherProviders {
		isolationRoot, err := os.MkdirTemp("", "toro-opencode-home-*")
		if err != nil {
			return fmt.Errorf("create temporary opencode isolation directory: %w", err)
		}
		defer os.RemoveAll(isolationRoot)
		if err := os.MkdirAll(isolationRoot, 0o755); err != nil {
			return fmt.Errorf("prepare temporary opencode isolation directory: %w", err)
		}

		tmp, err := os.CreateTemp("", "toro-opencode-config-*.json")
		if err != nil {
			return fmt.Errorf("create temporary opencode config: %w", err)
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.WriteString(configContent); err != nil {
			tmp.Close()
			return fmt.Errorf("write temporary opencode config: %w", err)
		}
		if err := tmp.Close(); err != nil {
			return fmt.Errorf("close temporary opencode config: %w", err)
		}

		xdgConfigHome := isolationRoot + "/config"
		xdgDataHome := isolationRoot + "/data"
		xdgCacheHome := isolationRoot + "/cache"
		if err := os.MkdirAll(xdgConfigHome, 0o755); err != nil {
			return fmt.Errorf("create temporary XDG config dir: %w", err)
		}
		if err := os.MkdirAll(xdgDataHome, 0o755); err != nil {
			return fmt.Errorf("create temporary XDG data dir: %w", err)
		}
		if err := os.MkdirAll(xdgCacheHome, 0o755); err != nil {
			return fmt.Errorf("create temporary XDG cache dir: %w", err)
		}

		env = append(env, "OPENCODE_CONFIG="+tmp.Name())
		env = append(env, "OPENCODE_DISABLE_PROJECT_CONFIG=1")
		env = append(env, "XDG_CONFIG_HOME="+xdgConfigHome)
		env = append(env, "XDG_DATA_HOME="+xdgDataHome)
		env = append(env, "XDG_CACHE_HOME="+xdgCacheHome)
	} else {
		env = append(env, "OPENCODE_CONFIG_CONTENT="+configContent)
	}
	proc.Env = env
	if err := proc.Run(); err != nil {
		return err
	}
	return nil
}

func runCodexWrap(cmd *cobra.Command, cfgPath, tokenName, model string, ttl time.Duration, codexArgs []string) error {
	cfg, err := config.LoadClientConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load client config (run `toro config` first): %w", err)
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return fmt.Errorf("client api key is required (set with: toro config)")
	}
	serverBase, err := deriveServerBaseURL(cfg.ServerURL)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		return fmt.Errorf("ttl must be > 0")
	}
	key, err := randomTemporaryKey()
	if err != nil {
		return fmt.Errorf("generate temporary key: %w", err)
	}
	if strings.TrimSpace(tokenName) == "" {
		tokenName = "toro-codex-" + time.Now().UTC().Format("20060102-150405")
	}
	expiresAt := time.Now().UTC().Add(ttl).Format(time.RFC3339)

	before, err := fetchAccessTokens(serverBase, cfg.APIKey)
	if err != nil {
		return fmt.Errorf("list access tokens before create: %w", err)
	}
	beforeIDs := map[string]struct{}{}
	for _, t := range before {
		beforeIDs[strings.TrimSpace(t.ID)] = struct{}{}
	}
	if err := createAccessToken(serverBase, cfg.APIKey, tokenName, key, "inferrer", expiresAt); err != nil {
		return fmt.Errorf("create temporary access token: %w", err)
	}
	tmpID, err := findCreatedTokenID(serverBase, cfg.APIKey, beforeIDs, tokenName, expiresAt)
	if err != nil {
		return fmt.Errorf("locate temporary access token id: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Created temporary token %q (id=%s, expires=%s)\n", tokenName, tmpID, expiresAt)

	cleanup := func() {
		if err := deleteAccessToken(serverBase, cfg.APIKey, tmpID); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: failed to delete temporary token %q (id=%s): %v\n", tokenName, tmpID, err)
			return
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Deleted temporary token %q (id=%s)\n", tokenName, tmpID)
	}
	defer cleanup()

	launchArgs := make([]string, 0, len(codexArgs)+8)
	launchArgs = append(launchArgs,
		"-c", `forced_login_method="api"`,
		"-c", `model_provider="tokenrouter"`,
		"-c", `model_providers.tokenrouter={name="TokenRouter",base_url=`+strconv.Quote(strings.TrimSuffix(serverBase, "/")+"/v1")+`,env_key="CODEX_API_KEY",wire_api="responses",requires_openai_auth=false}`,
	)
	launchArgs = append(launchArgs, codexArgs...)
	proc := exec.Command("codex", launchArgs...)
	proc.Stdin = cmd.InOrStdin()
	proc.Stdout = cmd.OutOrStdout()
	proc.Stderr = cmd.ErrOrStderr()
	env := filteredEnv([]string{
		"OPENAI_API_KEY",
		"OPENAI_BASE_URL",
		"OPENAI_API_BASE",
		"OPENAI_MODEL",
		"CODEX_API_KEY",
		"CODEX_BASE_URL",
		"CODEX_HOME",
	})
	env = append(env, "OPENAI_BASE_URL="+strings.TrimSuffix(serverBase, "/")+"/v1")
	env = append(env, "OPENAI_API_BASE="+strings.TrimSuffix(serverBase, "/")+"/v1")
	env = append(env, "OPENAI_API_KEY="+key)
	env = append(env, "CODEX_API_KEY="+key)
	env = append(env, "CODEX_BASE_URL="+strings.TrimSuffix(serverBase, "/")+"/v1")
	if strings.TrimSpace(model) != "" {
		env = append(env, "OPENAI_MODEL="+strings.TrimSpace(model))
	}
	proc.Env = env
	if err := proc.Run(); err != nil {
		return err
	}
	return nil
}

func runGenericWrap(cmd *cobra.Command, cfgPath, tokenName string, ttl time.Duration, urlEnvName, keyEnvName string, args []string) error {
	cfg, err := config.LoadClientConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load client config (run `toro config` first): %w", err)
	}
	key := strings.TrimSpace(cfg.APIKey)
	if key == "" {
		return fmt.Errorf("client api key is required (set with: toro config)")
	}
	serverBase, err := deriveServerBaseURL(cfg.ServerURL)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		return fmt.Errorf("ttl must be > 0")
	}
	urlEnvName = strings.TrimSpace(urlEnvName)
	keyEnvName = strings.TrimSpace(keyEnvName)
	if !isValidEnvVarName(urlEnvName) {
		return fmt.Errorf("invalid --url-env %q", urlEnvName)
	}
	if !isValidEnvVarName(keyEnvName) {
		return fmt.Errorf("invalid --key-env %q", keyEnvName)
	}

	targetCmd := strings.TrimSpace(args[0])
	if targetCmd == "" {
		return fmt.Errorf("command cannot be empty")
	}

	tmpKey, err := randomTemporaryKey()
	if err != nil {
		return fmt.Errorf("generate temporary key: %w", err)
	}
	if strings.TrimSpace(tokenName) == "" {
		tokenName = "toro-wrap-" + time.Now().UTC().Format("20060102-150405")
	}
	expiresAt := time.Now().UTC().Add(ttl).Format(time.RFC3339)

	before, err := fetchAccessTokens(serverBase, key)
	if err != nil {
		return fmt.Errorf("list access tokens before create: %w", err)
	}
	beforeIDs := map[string]struct{}{}
	for _, t := range before {
		beforeIDs[strings.TrimSpace(t.ID)] = struct{}{}
	}
	if err := createAccessToken(serverBase, key, tokenName, tmpKey, "inferrer", expiresAt); err != nil {
		return fmt.Errorf("create temporary access token: %w", err)
	}
	tmpID, err := findCreatedTokenID(serverBase, key, beforeIDs, tokenName, expiresAt)
	if err != nil {
		return fmt.Errorf("locate temporary access token id: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Created temporary token %q (id=%s, expires=%s)\n", tokenName, tmpID, expiresAt)

	cleanup := func() {
		if err := deleteAccessToken(serverBase, key, tmpID); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: failed to delete temporary token %q (id=%s): %v\n", tokenName, tmpID, err)
			return
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Deleted temporary token %q (id=%s)\n", tokenName, tmpID)
	}
	defer cleanup()

	proc := exec.Command(targetCmd, args[1:]...)
	proc.Stdin = cmd.InOrStdin()
	proc.Stdout = cmd.OutOrStdout()
	proc.Stderr = cmd.ErrOrStderr()
	env := filteredEnv([]string{urlEnvName, keyEnvName})
	env = append(env, urlEnvName+"="+strings.TrimSuffix(serverBase, "/")+"/v1")
	env = append(env, keyEnvName+"="+tmpKey)
	proc.Env = env
	if err := proc.Run(); err != nil {
		return err
	}
	return nil
}

func codexArgsContainForcedLoginMethod(args []string) bool {
	for i := 0; i < len(args); i++ {
		v := strings.TrimSpace(args[i])
		if v == "" {
			continue
		}
		if strings.HasPrefix(v, "-c") || strings.HasPrefix(v, "--config") {
			if strings.Contains(v, "forced_login_method") {
				return true
			}
			if (v == "-c" || v == "--config") && i+1 < len(args) {
				if strings.Contains(args[i+1], "forced_login_method") {
					return true
				}
			}
		}
	}
	return false
}

func filteredEnv(dropKeys []string) []string {
	if len(dropKeys) == 0 {
		return os.Environ()
	}
	drop := map[string]struct{}{}
	for _, k := range dropKeys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		drop[k] = struct{}{}
	}
	in := os.Environ()
	out := make([]string, 0, len(in))
	for _, e := range in {
		if i := strings.IndexByte(e, '='); i > 0 {
			if _, blocked := drop[e[:i]]; blocked {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

func isValidEnvVarName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if i == 0 {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '_' {
				continue
			}
			return false
		}
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return false
	}
	return true
}

func deriveServerBaseURL(serverURL string) (string, error) {
	serverURL = strings.TrimSpace(serverURL)
	if serverURL == "" {
		return "", fmt.Errorf("server_url is empty")
	}
	u, err := neturl.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("parse server_url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("server_url must be absolute, got %q", serverURL)
	}
	path := strings.TrimSpace(u.Path)
	path = strings.TrimSuffix(path, "/")
	if strings.HasSuffix(path, "/v1") {
		path = strings.TrimSuffix(path, "/v1")
	}
	u.Path = path
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	base := strings.TrimSuffix(u.String(), "/")
	return base, nil
}

func randomTemporaryKey() (string, error) {
	var b [48]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(b[:])
	return "tor_tmp_" + enc, nil
}

func adminAPIRequest(serverBase, bearer, method, path string, body any) (*http.Response, error) {
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimSuffix(serverBase, "/")+path, buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(bearer))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 20 * time.Second}
	return client.Do(req)
}

func fetchAccessTokens(serverBase, bearer string) ([]accessTokenItem, error) {
	r, err := adminAPIRequest(serverBase, bearer, http.MethodGet, "/admin/api/access-tokens", nil)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		return nil, formatAdminTokenAPIError(r.StatusCode, b)
	}
	var items []accessTokenItem
	if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
		return nil, err
	}
	return items, nil
}

func createAccessToken(serverBase, bearer, name, key, role, expiresAt string) error {
	payload := map[string]any{
		"name":       strings.TrimSpace(name),
		"key":        strings.TrimSpace(key),
		"role":       strings.TrimSpace(role),
		"expires_at": strings.TrimSpace(expiresAt),
	}
	r, err := adminAPIRequest(serverBase, bearer, http.MethodPost, "/admin/api/access-tokens", payload)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		return formatAdminTokenAPIError(r.StatusCode, b)
	}
	return nil
}

func findCreatedTokenID(serverBase, bearer string, beforeIDs map[string]struct{}, name, expiresAt string) (string, error) {
	for i := 0; i < 8; i++ {
		items, err := fetchAccessTokens(serverBase, bearer)
		if err != nil {
			return "", err
		}
		for _, t := range items {
			id := strings.TrimSpace(t.ID)
			if id == "" {
				continue
			}
			if _, existed := beforeIDs[id]; existed {
				continue
			}
			if strings.TrimSpace(t.Name) != strings.TrimSpace(name) {
				continue
			}
			if strings.TrimSpace(t.Role) != config.TokenRoleInferrer {
				continue
			}
			if strings.TrimSpace(t.ExpiresAt) != strings.TrimSpace(expiresAt) {
				continue
			}
			return id, nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return "", fmt.Errorf("temporary token not found after create")
}

func deleteAccessToken(serverBase, bearer, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("missing token id")
	}
	r, err := adminAPIRequest(serverBase, bearer, http.MethodDelete, "/admin/api/access-tokens/"+neturl.PathEscape(id), nil)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		return formatAdminTokenAPIError(r.StatusCode, b)
	}
	return nil
}

func formatAdminTokenAPIError(status int, body []byte) error {
	msg := strings.TrimSpace(string(body))
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		if msg == "" {
			msg = "unauthorized"
		}
		return fmt.Errorf("status %d: %s (toro wrappers require an admin or keymaster token in toro config)", status, msg)
	}
	if msg == "" {
		msg = http.StatusText(status)
	}
	return fmt.Errorf("status %d: %s", status, msg)
}

func buildOpencodeConfigContent(serverBase, tempKey, providerID, providerName, model string) (string, error) {
	injectedModel := strings.TrimSpace(model)
	if injectedModel != "" && !strings.Contains(injectedModel, "/") {
		injectedModel = providerID + "/" + injectedModel
	}
	payload := map[string]any{
		"provider": map[string]any{
			providerID: map[string]any{
				"name": providerName,
				"npm":  "@ai-sdk/openai-compatible",
				"options": map[string]any{
					"baseURL": strings.TrimSuffix(serverBase, "/") + "/v1",
					"apiKey":  tempKey,
				},
			},
		},
	}
	if injectedModel != "" {
		payload["model"] = injectedModel
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal opencode config content: %w", err)
	}
	return string(b), nil
}
