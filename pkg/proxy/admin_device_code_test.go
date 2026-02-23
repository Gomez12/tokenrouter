package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lkarlslund/openai-personal-proxy/pkg/config"
)

func TestProviderDeviceCodeAPIRequestsEndpointAndReturnsCode(t *testing.T) {
	var gotClientID string
	var gotScope string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/x-www-form-urlencoded") {
			t.Fatalf("expected form content-type, got %q", ct)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		gotClientID = r.Form.Get("client_id")
		gotScope = r.Form.Get("scope")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_code":"dev-123","user_code":"ABCD-EFGH","verification_uri":"https://example.com/device","expires_in":1800}`))
	}))
	defer upstream.Close()

	cfg := config.NewDefaultServerConfig()
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	h := &AdminHandler{store: store}

	body := `{"provider":"google-gemini","device_code_url":"` + upstream.URL + `","client_id":"client-xyz","scope":"openid email"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/providers/device-code", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.providerDeviceCodeAPI(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}
	if gotClientID != "client-xyz" {
		t.Fatalf("expected client_id client-xyz, got %q", gotClientID)
	}
	if gotScope != "openid email" {
		t.Fatalf("expected scope 'openid email', got %q", gotScope)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, response=%v", resp)
	}
	if userCode, _ := resp["user_code"].(string); userCode != "ABCD-EFGH" {
		t.Fatalf("expected user_code ABCD-EFGH, got %q", userCode)
	}
}

func TestProviderDeviceCodeAPIMissingClientID(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	h := &AdminHandler{store: store}

	body := `{"provider":"google-gemini","device_code_url":"https://oauth2.googleapis.com/device/code","client_id":"","scope":"openid email"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/providers/device-code", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.providerDeviceCodeAPI(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(strings.ToLower(w.Body.String()), "client_id") {
		t.Fatalf("expected client_id error, got %q", w.Body.String())
	}
}
