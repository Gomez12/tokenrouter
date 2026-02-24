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
	"github.com/lkarlslund/tokenrouter/pkg/config"
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
			if strings.TrimSpace(asString(it["redacted_key"])) == "********" {
				foundRedaction = true
			}
		}
	}
	if addedID == "" {
		t.Fatal("added token not found in list")
	}
	if !foundRedaction {
		t.Fatal("expected redacted key to be fixed 8 asterisks")
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

func TestAccessTokensAPIKeymasterOnlySeesAndManagesOwnSubordinates(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	cfg.IncomingTokens = []config.IncomingAPIToken{
		{ID: "km-1", Name: "KM", Key: "km-key", Role: config.TokenRoleKeymaster},
		{ID: "child-1", Name: "Child 1", Key: "child1", Role: config.TokenRoleInferrer, ParentID: "km-1"},
		{ID: "child-2", Name: "Child 2", Key: "child2", Role: config.TokenRoleInferrer, ParentID: "km-2"},
	}
	store := config.NewServerConfigStore(filepath.Join(t.TempDir(), "config.toml"), cfg)
	h := &AdminHandler{store: store}

	actor := tokenAuthIdentity{
		Role: config.TokenRoleKeymaster,
		Token: config.IncomingAPIToken{
			ID:   "km-1",
			Name: "KM",
			Role: config.TokenRoleKeymaster,
		},
	}

	listReq := httptest.NewRequest(http.MethodGet, "/admin/api/access-tokens", nil)
	listReq = listReq.WithContext(context.WithValue(listReq.Context(), adminAuthContextKey{}, actor))
	listW := httptest.NewRecorder()
	h.accessTokensAPI(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200 from list, got %d body=%s", listW.Code, listW.Body.String())
	}
	var items []map[string]any
	if err := json.Unmarshal(listW.Body.Bytes(), &items); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected keymaster to see 1 subordinate token, got %d (%v)", len(items), items)
	}
	if strings.TrimSpace(asString(items[0]["id"])) != "child-1" {
		t.Fatalf("expected to only see child-1, got %+v", items[0])
	}

	addReq := httptest.NewRequest(http.MethodPost, "/admin/api/access-tokens", strings.NewReader(`{"name":"Child New","key":"abcd987654","expires_at":"2026-03-01T10:00:00Z"}`))
	addReq.Header.Set("Content-Type", "application/json")
	addReq = addReq.WithContext(context.WithValue(addReq.Context(), adminAuthContextKey{}, actor))
	addW := httptest.NewRecorder()
	h.accessTokensAPI(addW, addReq)
	if addW.Code != http.StatusCreated {
		t.Fatalf("expected 201 from add, got %d body=%s", addW.Code, addW.Body.String())
	}

	snap := store.Snapshot()
	var created *config.IncomingAPIToken
	for i := range snap.IncomingTokens {
		if strings.TrimSpace(snap.IncomingTokens[i].Name) == "Child New" {
			created = &snap.IncomingTokens[i]
			break
		}
	}
	if created == nil {
		t.Fatal("expected created subordinate token")
	}
	if created.ParentID != "km-1" {
		t.Fatalf("expected created token parent_id km-1, got %q", created.ParentID)
	}
	if created.Role != config.TokenRoleInferrer {
		t.Fatalf("expected created token role inferrer, got %q", created.Role)
	}

	delForeignReq := httptest.NewRequest(http.MethodDelete, "/admin/api/access-tokens/child-2", nil)
	delForeignCtx := chi.NewRouteContext()
	delForeignCtx.URLParams.Add("id", "child-2")
	delForeignReq = delForeignReq.WithContext(context.WithValue(context.WithValue(delForeignReq.Context(), chi.RouteCtxKey, delForeignCtx), adminAuthContextKey{}, actor))
	delForeignW := httptest.NewRecorder()
	h.accessTokenByIDAPI(delForeignW, delForeignReq)
	if delForeignW.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when deleting foreign child, got %d body=%s", delForeignW.Code, delForeignW.Body.String())
	}

	delOwnReq := httptest.NewRequest(http.MethodDelete, "/admin/api/access-tokens/child-1", nil)
	delOwnCtx := chi.NewRouteContext()
	delOwnCtx.URLParams.Add("id", "child-1")
	delOwnReq = delOwnReq.WithContext(context.WithValue(context.WithValue(delOwnReq.Context(), chi.RouteCtxKey, delOwnCtx), adminAuthContextKey{}, actor))
	delOwnW := httptest.NewRecorder()
	h.accessTokenByIDAPI(delOwnW, delOwnReq)
	if delOwnW.Code != http.StatusOK {
		t.Fatalf("expected 200 when deleting own child, got %d body=%s", delOwnW.Code, delOwnW.Body.String())
	}
}
