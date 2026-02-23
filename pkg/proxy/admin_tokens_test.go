package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/lkarlslund/openai-personal-proxy/pkg/config"
)

func TestAccessTokensAPIAddListDelete(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	cfg.IncomingTokens = []config.IncomingAPIToken{
		{ID: "tok-initial", Name: "Initial", Key: "init-secret"},
	}
	store := config.NewServerConfigStore(filepath.Join(t.TempDir(), "config.toml"), cfg)
	h := &AdminHandler{store: store}

	addReq := httptest.NewRequest(http.MethodPost, "/admin/api/access-tokens", strings.NewReader(`{"name":"Dev","key":"abcd123456","expires_at":"2026-03-01T10:00:00Z"}`))
	addReq.Header.Set("Content-Type", "application/json")
	addW := httptest.NewRecorder()
	h.accessTokensAPI(addW, addReq)
	if addW.Code != http.StatusCreated {
		t.Fatalf("expected 201 from add, got %d body=%s", addW.Code, addW.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/admin/api/access-tokens", nil)
	listW := httptest.NewRecorder()
	h.accessTokensAPI(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200 from list, got %d body=%s", listW.Code, listW.Body.String())
	}
	var items []map[string]any
	if err := json.Unmarshal(listW.Body.Bytes(), &items); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(items))
	}
	var addedID string
	foundRedaction := false
	for _, it := range items {
		if strings.TrimSpace(asString(it["name"])) == "Dev" {
			addedID = strings.TrimSpace(asString(it["id"]))
			if strings.TrimSpace(asString(it["redacted_key"])) == "abcd******" {
				foundRedaction = true
			}
		}
	}
	if addedID == "" {
		t.Fatal("added token not found in list")
	}
	if !foundRedaction {
		t.Fatal("expected redacted key format first4 + asterisks")
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/admin/api/access-tokens/"+addedID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", addedID)
	delReq = delReq.WithContext(context.WithValue(delReq.Context(), chi.RouteCtxKey, rctx))
	delW := httptest.NewRecorder()
	h.accessTokenByIDAPI(delW, delReq)
	if delW.Code != http.StatusOK {
		t.Fatalf("expected 200 from delete, got %d body=%s", delW.Code, delW.Body.String())
	}
}

func TestAccessTokensAPIRejectsMissingName(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	store := config.NewServerConfigStore(filepath.Join(t.TempDir(), "config.toml"), cfg)
	h := &AdminHandler{store: store}

	req := httptest.NewRequest(http.MethodPost, "/admin/api/access-tokens", strings.NewReader(`{"name":"","key":"abcd123456"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.accessTokensAPI(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing name, got %d body=%s", w.Code, w.Body.String())
	}
}
