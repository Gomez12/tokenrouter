package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lkarlslund/tokenrouter/pkg/config"
	"github.com/spf13/cobra"
)

func TestIsValidEnvVarName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{name: "empty", in: "", ok: false},
		{name: "leading digit", in: "1OPENAI", ok: false},
		{name: "contains dash", in: "OPENAI-KEY", ok: false},
		{name: "contains space", in: "OPENAI KEY", ok: false},
		{name: "simple", in: "OPENAI_API_KEY", ok: true},
		{name: "lowercase", in: "openai_base_url", ok: true},
		{name: "leading underscore", in: "_TOKEN", ok: true},
		{name: "with digits", in: "API_KEY_2", ok: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidEnvVarName(tc.in); got != tc.ok {
				t.Fatalf("isValidEnvVarName(%q) = %v, want %v", tc.in, got, tc.ok)
			}
		})
	}
}

func TestRunModelsHuman(t *testing.T) {
	const apiKey = "test-key"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		if got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer")); got != apiKey {
			t.Fatalf("authorization header mismatch: got %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"zeta/mini","object":"model"},{"id":"alpha/base","object":"model"}]}`))
	}))
	defer srv.Close()

	cfgPath := filepath.Join(t.TempDir(), "toro.toml")
	if err := config.Save(cfgPath, &config.ClientConfig{
		ServerURL: strings.TrimRight(srv.URL, "/") + "/v1",
		APIKey:    apiKey,
	}); err != nil {
		t.Fatalf("save config: %v", err)
	}

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := runModels(cmd, cfgPath, false); err != nil {
		t.Fatalf("runModels: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "Models: 2") {
		t.Fatalf("expected count in output, got:\n%s", got)
	}
	if !strings.Contains(got, "  - alpha/base") || !strings.Contains(got, "  - zeta/mini") {
		t.Fatalf("expected models in output, got:\n%s", got)
	}
	if strings.Index(got, "alpha/base") > strings.Index(got, "zeta/mini") {
		t.Fatalf("expected sorted models in output, got:\n%s", got)
	}
}

func TestRunModelsJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"p/a","object":"model","provider":"p"},{"id":"p/b","object":"model","provider":"p"}]}`))
	}))
	defer srv.Close()

	cfgPath := filepath.Join(t.TempDir(), "toro.toml")
	if err := config.Save(cfgPath, &config.ClientConfig{
		ServerURL: strings.TrimRight(srv.URL, "/"),
		APIKey:    "unused",
	}); err != nil {
		t.Fatalf("save config: %v", err)
	}

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := runModels(cmd, cfgPath, true); err != nil {
		t.Fatalf("runModels json: %v", err)
	}
	var report modelsReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("decode json output: %v\n%s", err, out.String())
	}
	if report.Count != 2 {
		t.Fatalf("count = %d, want 2", report.Count)
	}
	if len(report.Models) != 2 || report.Models[0].ID != "p/a" || report.Models[1].ID != "p/b" {
		t.Fatalf("unexpected models: %+v", report.Models)
	}
}
