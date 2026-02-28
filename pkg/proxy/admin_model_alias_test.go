package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/lkarlslund/tokenrouter/pkg/config"
)

func TestAdminModelAliasesAPIListsAndSwitchesActiveProfile(t *testing.T) {
	isolateDefaultDataPaths(t)
	cfg := config.NewDefaultServerConfig()
	cfg.AllowLocalhostNoAuth = false
	cfg.ActiveModelProfile = "local"
	cfg.IncomingTokens = []config.IncomingAPIToken{{ID: "adm", Name: "Admin", Key: "adm-key", Role: config.TokenRoleAdmin}}
	cfg.Providers = []config.ProviderConfig{
		{Name: "ollama", BaseURL: "http://localhost:11434/v1", Enabled: true},
		{Name: "runpod-main", BaseURL: "https://runpod.example/v1", Enabled: true},
	}
	cfg.ModelAliases = []config.ModelAliasConfig{
		{
			Name: "chat",
			Targets: []config.ModelAliasTarget{
				{Profile: "local", Provider: "ollama", Model: "qwen2.5:14b"},
				{Profile: "runpod", Provider: "runpod-main", Model: "Qwen/Qwen2.5-14B-Instruct"},
			},
		},
	}
	s, err := NewServer(filepath.Join(t.TempDir(), "torod.toml"), cfg)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/api/model-aliases", nil)
	req.Header.Set("Authorization", "Bearer adm-key")
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected GET 200, got %d body=%s", w.Code, w.Body.String())
	}
	var listBody struct {
		ActiveModelProfile string   `json:"active_model_profile"`
		AvailableProfiles  []string `json:"available_profiles"`
		Data               []struct {
			Name         string                   `json:"name"`
			ActiveTarget *config.ModelAliasTarget `json:"active_target"`
			Status       string                   `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("decode list body: %v", err)
	}
	if listBody.ActiveModelProfile != "local" {
		t.Fatalf("expected active profile local, got %q", listBody.ActiveModelProfile)
	}
	if len(listBody.AvailableProfiles) != 2 {
		t.Fatalf("expected 2 profiles, got %v", listBody.AvailableProfiles)
	}
	if len(listBody.Data) != 1 || listBody.Data[0].ActiveTarget == nil || listBody.Data[0].ActiveTarget.Provider != "ollama" {
		t.Fatalf("unexpected alias list body: %+v", listBody)
	}

	payload := []byte(`{"active_model_profile":"runpod"}`)
	req = httptest.NewRequest(http.MethodPut, "/admin/api/model-aliases/settings", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer adm-key")
	w = httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected PUT settings 200, got %d body=%s", w.Code, w.Body.String())
	}
	var settingsBody struct {
		ActiveModelProfile string `json:"active_model_profile"`
		Data               []struct {
			ActiveTarget *config.ModelAliasTarget `json:"active_target"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &settingsBody); err != nil {
		t.Fatalf("decode settings body: %v", err)
	}
	if settingsBody.ActiveModelProfile != "runpod" {
		t.Fatalf("expected switched active profile runpod, got %q", settingsBody.ActiveModelProfile)
	}
	if len(settingsBody.Data) != 1 || settingsBody.Data[0].ActiveTarget == nil || settingsBody.Data[0].ActiveTarget.Provider != "runpod-main" {
		t.Fatalf("expected runpod target after switch, got %+v", settingsBody)
	}
}

func TestAdminModelAliasesAPICRUD(t *testing.T) {
	isolateDefaultDataPaths(t)
	cfg := config.NewDefaultServerConfig()
	cfg.AllowLocalhostNoAuth = false
	cfg.ActiveModelProfile = "local"
	cfg.IncomingTokens = []config.IncomingAPIToken{{ID: "adm", Name: "Admin", Key: "adm-key", Role: config.TokenRoleAdmin}}
	s, err := NewServer(filepath.Join(t.TempDir(), "torod.toml"), cfg)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	postBody := []byte(`{"name":"chat","targets":[{"profile":"local","provider":"ollama","model":"qwen2.5:14b"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/model-aliases", bytes.NewReader(postBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer adm-key")
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected POST 201, got %d body=%s", w.Code, w.Body.String())
	}

	putBody := []byte(`{"name":"chat","targets":[{"profile":"local","provider":"ollama","model":"llama3.2"}]}`)
	req = httptest.NewRequest(http.MethodPut, "/admin/api/model-aliases/chat", bytes.NewReader(putBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer adm-key")
	w = httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected PUT 200, got %d body=%s", w.Code, w.Body.String())
	}
	var putResp struct {
		Data []struct {
			Targets []config.ModelAliasTarget `json:"targets"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &putResp); err != nil {
		t.Fatalf("decode put body: %v", err)
	}
	if len(putResp.Data) != 1 || len(putResp.Data[0].Targets) != 1 || putResp.Data[0].Targets[0].Model != "llama3.2" {
		t.Fatalf("expected updated alias target, got %+v", putResp)
	}

	req = httptest.NewRequest(http.MethodDelete, "/admin/api/model-aliases/chat", nil)
	req.Header.Set("Authorization", "Bearer adm-key")
	w = httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected DELETE 200, got %d body=%s", w.Code, w.Body.String())
	}
	var deleteResp struct {
		Data []any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &deleteResp); err != nil {
		t.Fatalf("decode delete body: %v", err)
	}
	if len(deleteResp.Data) != 0 {
		t.Fatalf("expected empty alias list after delete, got %+v", deleteResp)
	}
}

func TestAdminModelAliasesAPICreateWithoutActiveProfileReturnsClearError(t *testing.T) {
	isolateDefaultDataPaths(t)
	cfg := config.NewDefaultServerConfig()
	cfg.AllowLocalhostNoAuth = false
	cfg.IncomingTokens = []config.IncomingAPIToken{{ID: "adm", Name: "Admin", Key: "adm-key", Role: config.TokenRoleAdmin}}
	s, err := NewServer(filepath.Join(t.TempDir(), "torod.toml"), cfg)
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}

	postBody := []byte(`{"name":"chat","targets":[{"profile":"local","provider":"ollama","model":"qwen2.5:14b"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/model-aliases", bytes.NewReader(postBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer adm-key")
	w := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected POST 400, got %d body=%s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); body != "set active_model_profile before creating model aliases\n" {
		t.Fatalf("unexpected error body: %q", body)
	}
}
