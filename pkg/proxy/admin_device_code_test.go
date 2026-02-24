package proxy

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lkarlslund/tokenrouter/pkg/config"
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

func TestProviderDeviceTokenAPIReturnsAccessToken(t *testing.T) {
	var gotClientID string
	var gotDeviceCode string
	var gotGrantType string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); strings.Contains(ct, "application/json") {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode json: %v", err)
			}
			gotClientID = strings.TrimSpace(asString(body["client_id"]))
			gotDeviceCode = strings.TrimSpace(asString(body["device_code"]))
			gotGrantType = strings.TrimSpace(asString(body["grant_type"]))
		} else {
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse form: %v", err)
			}
			gotClientID = r.Form.Get("client_id")
			gotDeviceCode = r.Form.Get("device_code")
			gotGrantType = r.Form.Get("grant_type")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gho_test","expires_in":28800}`))
	}))
	defer upstream.Close()

	cfg := config.NewDefaultServerConfig()
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	h := &AdminHandler{store: store}

	body := `{"provider":"github-copilot","device_token_url":"` + upstream.URL + `","client_id":"cid","device_code":"dcode"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/providers/device-token", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.providerDeviceTokenAPI(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}
	if gotClientID != "cid" || gotDeviceCode != "dcode" {
		t.Fatalf("unexpected form values client_id=%q device_code=%q", gotClientID, gotDeviceCode)
	}
	if gotGrantType != "urn:ietf:params:oauth:grant-type:device_code" {
		t.Fatalf("unexpected grant_type: %q", gotGrantType)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, response=%v", resp)
	}
	if pending, _ := resp["pending"].(bool); pending {
		t.Fatalf("expected pending=false, response=%v", resp)
	}
	if token, _ := resp["auth_token"].(string); token != "gho_test" {
		t.Fatalf("expected auth_token gho_test, got %q", token)
	}
}

func TestProviderDeviceTokenAPIPending(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"authorization_pending","interval":5}`))
	}))
	defer upstream.Close()

	cfg := config.NewDefaultServerConfig()
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	h := &AdminHandler{store: store}

	body := `{"provider":"github-copilot","device_token_url":"` + upstream.URL + `","client_id":"cid","device_code":"dcode"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/providers/device-token", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.providerDeviceTokenAPI(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if pending, _ := resp["pending"].(bool); !pending {
		t.Fatalf("expected pending=true, response=%v", resp)
	}
}

func TestProviderDeviceCodeAPIOpenAIMapsDeviceAuthID(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Fatalf("expected json content-type, got %q", ct)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if got := strings.TrimSpace(body["client_id"].(string)); got == "" {
			t.Fatal("expected client_id")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_auth_id":"auth_123","user_code":"ABCD-EFGH","interval":"5"}`))
	}))
	defer upstream.Close()

	cfg := config.NewDefaultServerConfig()
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	h := &AdminHandler{store: store}

	body := `{"provider":"openai","device_code_url":"` + upstream.URL + `","client_id":"app_x","scope":"openid profile email offline_access"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/providers/device-code", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.providerDeviceCodeAPI(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got := strings.TrimSpace(asString(resp["device_auth_id"])); got != "auth_123" {
		t.Fatalf("expected device_auth_id auth_123, got %q", got)
	}
	if got := strings.TrimSpace(asString(resp["user_code"])); got != "ABCD-EFGH" {
		t.Fatalf("expected user_code ABCD-EFGH, got %q", got)
	}
	if got := strings.TrimSpace(asString(resp["verification_uri"])); got == "" {
		t.Fatal("expected verification_uri fallback")
	}
}

func TestProviderDeviceTokenAPIOpenAITwoStage(t *testing.T) {
	deviceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Fatalf("expected json content-type, got %q", ct)
		}
		_, _ = w.Write([]byte(`{"authorization_code":"authcode-123","code_verifier":"verifier-xyz"}`))
	}))
	defer deviceServer.Close()

	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acc_test_1"}}`))
	idToken := "a." + claims + ".c"
	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "authorization_code" {
			t.Fatalf("unexpected grant_type: %q", got)
		}
		if got := r.Form.Get("code"); got != "authcode-123" {
			t.Fatalf("unexpected code: %q", got)
		}
		if got := r.Form.Get("code_verifier"); got != "verifier-xyz" {
			t.Fatalf("unexpected code_verifier: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at_123","refresh_token":"rt_123","expires_in":3600,"id_token":"` + idToken + `"}`))
	}))
	defer oauthServer.Close()

	cfg := config.NewDefaultServerConfig()
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	h := &AdminHandler{store: store}

	body := `{"provider":"openai","device_token_url":"` + deviceServer.URL + `","oauth_token_url":"` + oauthServer.URL + `","client_id":"app_x","device_code":"ABCD-EFGH","device_auth_id":"auth_123"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/providers/device-token", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.providerDeviceTokenAPI(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got := strings.TrimSpace(asString(resp["auth_token"])); got != "at_123" {
		t.Fatalf("unexpected auth_token: %q", got)
	}
	if got := strings.TrimSpace(asString(resp["refresh_token"])); got != "rt_123" {
		t.Fatalf("unexpected refresh_token: %q", got)
	}
	if got := strings.TrimSpace(asString(resp["account_id"])); got != "acc_test_1" {
		t.Fatalf("unexpected account_id: %q", got)
	}
}
