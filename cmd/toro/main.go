package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/tokenrouter/pkg/config"
	"github.com/lkarlslund/tokenrouter/pkg/logutil"
	"github.com/lkarlslund/tokenrouter/pkg/version"
	"github.com/spf13/cobra"
)

func main() {
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

	var clientConfigPath string
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Configure remote TokenRouter server URL and API key",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigTUI(cmd, clientConfigPath)
		},
	}
	configCmd.Flags().StringVar(&clientConfigPath, "config", config.DefaultClientConfigPath(), "Client config TOML path")
	root.AddCommand(configCmd)
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

	var opencodeConfigPath string
	var opencodeTokenName string
	var opencodeProviderID string
	var opencodeProviderName string
	var opencodeModel string
	var opencodeTTL time.Duration
	var opencodeDisableOtherProviders bool
	opencodeCmd := &cobra.Command{
		Use:   "opencode [-- opencode_args...]",
		Short: "Launch opencode with a temporary subordinate TokenRouter key",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOpencodeWrap(cmd, opencodeConfigPath, opencodeTokenName, opencodeProviderID, opencodeProviderName, opencodeModel, opencodeTTL, opencodeDisableOtherProviders, args)
		},
	}
	opencodeCmd.FParseErrWhitelist.UnknownFlags = true
	opencodeCmd.Flags().SetInterspersed(false)
	opencodeCmd.Flags().StringVar(&opencodeConfigPath, "config", config.DefaultClientConfigPath(), "Client config TOML path")
	opencodeCmd.Flags().StringVar(&opencodeTokenName, "name", "", "Temporary token name (default: auto-generated unique name)")
	opencodeCmd.Flags().StringVar(&opencodeProviderID, "provider-id", "tokenrouter", "Injected opencode provider id")
	opencodeCmd.Flags().StringVar(&opencodeProviderName, "provider-name", "TokenRouter", "Injected opencode provider display name")
	opencodeCmd.Flags().StringVar(&opencodeModel, "model", "", "Optional model to select (bare model id or provider/model)")
	opencodeCmd.Flags().DurationVar(&opencodeTTL, "ttl", 8*time.Hour, "Temporary token expiry duration")
	opencodeCmd.Flags().BoolVar(&opencodeDisableOtherProviders, "disable-other-providers", true, "Disable all other opencode providers while wrapped")
	root.AddCommand(opencodeCmd)

	var codexConfigPath string
	var codexTokenName string
	var codexModel string
	var codexTTL time.Duration
	codexCmd := &cobra.Command{
		Use:   "codex [-- codex_args...]",
		Short: "Launch codex-cli with a temporary subordinate TokenRouter key",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCodexWrap(cmd, codexConfigPath, codexTokenName, codexModel, codexTTL, args)
		},
	}
	codexCmd.FParseErrWhitelist.UnknownFlags = true
	codexCmd.Flags().SetInterspersed(false)
	codexCmd.Flags().StringVar(&codexConfigPath, "config", config.DefaultClientConfigPath(), "Client config TOML path")
	codexCmd.Flags().StringVar(&codexTokenName, "name", "", "Temporary token name (default: auto-generated unique name)")
	codexCmd.Flags().StringVar(&codexModel, "model", "", "Optional model override passed via OPENAI_MODEL")
	codexCmd.Flags().DurationVar(&codexTTL, "ttl", 8*time.Hour, "Temporary token expiry duration")
	root.AddCommand(codexCmd)

	var wrapConfigPath string
	var wrapURLEnv string
	var wrapKeyEnv string
	wrapCmd := &cobra.Command{
		Use:   "wrap [flags] <command> [args...]",
		Short: "Run any command with TokenRouter URL and API key env vars",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenericWrap(cmd, wrapConfigPath, wrapURLEnv, wrapKeyEnv, args)
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
	cfg, err := config.LoadOrCreateClientConfig(path)
	if err != nil {
		return fmt.Errorf("load client config: %w", err)
	}
	reader := bufio.NewReader(cmd.InOrStdin())
	out := cmd.OutOrStdout()

	fmt.Fprintf(out, "Toro client config: %s\n", path)
	fmt.Fprintln(out, "Press Enter to keep current value.")
	fmt.Fprintln(out, "Enter '-' for API key to clear it.")

	serverURL, err := promptLine(reader, out, fmt.Sprintf("Remote server URL [%s]: ", cfg.ServerURL))
	if err != nil {
		return err
	}
	serverURL = strings.TrimSpace(serverURL)
	if serverURL != "" {
		cfg.ServerURL = serverURL
	}

	apiKeyPrompt := "API key [not set]: "
	if strings.TrimSpace(cfg.APIKey) != "" {
		redacted := strings.TrimSpace(cfg.APIKey)
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
		// keep existing value
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

func runGenericWrap(cmd *cobra.Command, cfgPath, urlEnvName, keyEnvName string, args []string) error {
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
	proc := exec.Command(targetCmd, args[1:]...)
	proc.Stdin = cmd.InOrStdin()
	proc.Stdout = cmd.OutOrStdout()
	proc.Stderr = cmd.ErrOrStderr()
	env := filteredEnv([]string{urlEnvName, keyEnvName})
	env = append(env, urlEnvName+"="+strings.TrimSuffix(serverBase, "/")+"/v1")
	env = append(env, keyEnvName+"="+key)
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
