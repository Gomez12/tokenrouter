package tests

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	openai "github.com/sashabaranov/go-openai"

	"github.com/lkarlslund/openai-personal-proxy/pkg/config"
)

func testRepoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller")
	}
	return filepath.Dir(filepath.Dir(filename))
}

func waitForReady(ctx context.Context, healthURL string) error {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func findFreeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick free port: %v", err)
	}
	defer l.Close()
	return l.Addr().String()
}

func listModelIDs(t *testing.T, baseURL string) []string {
	t.Helper()
	cfg := openai.DefaultConfig("")
	cfg.BaseURL = strings.TrimRight(baseURL, "/") + "/v1"
	client := openai.NewClientWithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	models, err := client.ListModels(ctx)
	if err != nil {
		t.Fatalf("list models: %v", err)
	}
	ids := make([]string, 0, len(models.Models))
	for _, m := range models.Models {
		ids = append(ids, m.ID)
	}
	return ids
}

func requireContainsAll(t *testing.T, ids []string, expected ...string) {
	t.Helper()
	seen := map[string]struct{}{}
	for _, id := range ids {
		seen[id] = struct{}{}
	}
	for _, e := range expected {
		if _, ok := seen[e]; !ok {
			t.Fatalf("expected model %q in %v", e, ids)
		}
	}
}

func requireProviderModelIDs(t *testing.T, ids []string) {
	t.Helper()
	for _, id := range ids {
		parts := strings.SplitN(id, "/", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			t.Fatalf("model id %q is not in provider/model format", id)
		}
	}
}

func sendShortChat(t *testing.T, baseURL, model string) string {
	t.Helper()
	cfg := openai.DefaultConfig("")
	cfg.BaseURL = strings.TrimRight(baseURL, "/") + "/v1"
	client := openai.NewClientWithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req := openai.ChatCompletionRequest{
		Model: model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleUser, Content: "hi"},
		},
		MaxTokens: 16,
	}
	t.Logf("e2e chat request: model=%q messages=%v max_tokens=%d", req.Model, req.Messages, req.MaxTokens)
	resp, err := client.CreateChatCompletion(ctx, req)
	if err != nil {
		t.Fatalf("chat completion: %v", err)
	}
	t.Logf("e2e chat response: id=%q model=%q choices=%v usage=%+v", resp.ID, resp.Model, resp.Choices, resp.Usage)
	if len(resp.Choices) == 0 {
		t.Fatal("chat completion returned no choices")
	}
	content := strings.TrimSpace(resp.Choices[0].Message.Content)
	if content == "" {
		t.Fatal("chat completion returned empty content")
	}
	return content
}

func getSecuritySettings(t *testing.T, baseURL, adminKey string) string {
	t.Helper()
	u := fmt.Sprintf("%s/admin/api/settings/security?key=%s", strings.TrimRight(baseURL, "/"), adminKey)
	resp, err := http.Get(u) // #nosec G107
	if err != nil {
		t.Fatalf("get security settings: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read security settings: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("security settings status %d: %s", resp.StatusCode, string(b))
	}
	return string(b)
}

func TestCLIOverridesModelsFlow(t *testing.T) {
	t.Parallel()

	providerA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			_, _ = w.Write([]byte(`{"data":[{"id":"alpha"},{"id":"alpha-chat"},{"id":"alpha-lite"}]}`))
		case "/v1/chat/completions":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"chatcmpl-test","object":"chat.completion","created":1735689600,"model":"alpha-chat","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer providerA.Close()

	providerB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"bravo"},{"id":"bravo-mini"}]}`))
	}))
	defer providerB.Close()

	addr := findFreeAddr(t)
	cfg := config.NewDefaultServerConfig()
	cfg.ListenAddr = "127.0.0.1:1"
	cfg.AdminAPIKey = "admin-test-key"
	cfg.AllowLocalhostNoAuth = false
	cfg.AutoEnablePublicFreeModels = false
	cfg.Providers = []config.ProviderConfig{
		{Name: "provider-a", BaseURL: providerA.URL, Enabled: true, TimeoutSeconds: 2},
		{Name: "provider-b", BaseURL: providerB.URL, Enabled: true, TimeoutSeconds: 2},
	}

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "server.toml")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	repoRoot := testRepoRoot(t)
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

	cmd := exec.CommandContext(
		runCtx,
		"go", "run", "./cmd/openai-personal-proxy", "serve",
		"--config", cfgPath,
		"--listen-addr", addr,
		"--allow-localhost-no-auth=true",
		"--auto-enable-public-free-models=true",
	)
	cmd.Dir = repoRoot
	cmd.Env = os.Environ()

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	t.Cleanup(func() {
		runCancel()
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(io.Discard, stderrPipe)
			_, _ = io.Copy(io.Discard, stdoutPipe)
			_ = cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
		}
	})

	baseURL := "http://" + addr
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer readyCancel()
	if err := waitForReady(readyCtx, baseURL+"/healthz"); err != nil {
		t.Fatalf("proxy health check failed: %v", err)
	}

	ids := listModelIDs(t, baseURL)
	if len(ids) < 5 {
		t.Fatalf("expected at least 5 models, got %d (%v)", len(ids), ids)
	}
	requireProviderModelIDs(t, ids)
	requireContainsAll(t, ids, "provider-a/alpha", "provider-a/alpha-chat", "provider-b/bravo", "provider-b/bravo-mini")
	out := sendShortChat(t, baseURL, "provider-a/alpha-chat")
	if out == "" {
		t.Fatal("expected non-empty chat response content")
	}

	sec := getSecuritySettings(t, baseURL, cfg.AdminAPIKey)
	if !strings.Contains(sec, `"allow_localhost_no_auth":true`) {
		t.Fatalf("expected allow_localhost_no_auth override in %s", sec)
	}
	if !strings.Contains(sec, `"auto_enable_public_free_models":true`) {
		t.Fatalf("expected auto_enable_public_free_models override in %s", sec)
	}
}
