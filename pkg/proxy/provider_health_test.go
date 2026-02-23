package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/openai-personal-proxy/pkg/config"
)

func TestProviderHealthCheckerCheckOnceRecordsOnlineStatusAndLatency(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"gpt-5-nano"}]}`))
	}))
	defer srv.Close()

	cfg := config.NewDefaultServerConfig()
	cfg.Providers = []config.ProviderConfig{{
		Name:           "demo",
		BaseURL:        srv.URL,
		Enabled:        true,
		TimeoutSeconds: 2,
	}}
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	resolver := NewProviderResolver(store)
	checker := NewProviderHealthChecker(resolver, time.Hour)

	checker.checkOnce(context.Background(), false)

	snap, ok := checker.Snapshot("demo")
	if !ok {
		t.Fatal("expected provider health snapshot for demo provider")
	}
	if snap.Status != "online" {
		t.Fatalf("expected online status, got %q", snap.Status)
	}
	if snap.ModelCount != 1 {
		t.Fatalf("expected model count 1, got %d", snap.ModelCount)
	}
	if snap.ResponseMS <= 0 {
		t.Fatalf("expected positive response time, got %d ms", snap.ResponseMS)
	}
	if snap.CheckedAt.IsZero() {
		t.Fatal("expected checked_at timestamp to be set")
	}
}

func TestProviderHealthCheckerCheckOnceRecordsAuthProblem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "invalid api key", http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := config.NewDefaultServerConfig()
	cfg.Providers = []config.ProviderConfig{{
		Name:           "secured",
		BaseURL:        srv.URL,
		Enabled:        true,
		TimeoutSeconds: 2,
	}}
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	resolver := NewProviderResolver(store)
	checker := NewProviderHealthChecker(resolver, time.Hour)

	checker.checkOnce(context.Background(), false)

	snap, ok := checker.Snapshot("secured")
	if !ok {
		t.Fatal("expected provider health snapshot for secured provider")
	}
	if snap.Status != "auth problem" {
		t.Fatalf("expected auth problem status, got %q", snap.Status)
	}
}

func TestProviderHealthCheckerRecordProxyResultAndAvailabilitySummary(t *testing.T) {
	cfg := config.NewDefaultServerConfig()
	cfg.Providers = []config.ProviderConfig{
		{Name: "a", BaseURL: "http://a.invalid", Enabled: true, TimeoutSeconds: 2},
		{Name: "b", BaseURL: "http://b.invalid", Enabled: true, TimeoutSeconds: 2},
	}
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	resolver := NewProviderResolver(store)
	checker := NewProviderHealthChecker(resolver, time.Hour)

	checker.RecordProxyResult("a", 40*time.Millisecond, http.StatusOK, nil)
	checker.RecordProxyResult("b", 0, 0, errors.New("dial error"))

	a, ok := checker.Snapshot("a")
	if !ok || a.Status != "online" {
		t.Fatalf("expected provider a online, got ok=%v status=%q", ok, a.Status)
	}
	b, ok := checker.Snapshot("b")
	if !ok || b.Status != "offline" {
		t.Fatalf("expected provider b offline, got ok=%v status=%q", ok, b.Status)
	}

	available, online := checker.AvailabilitySummary([]string{"a", "b"})
	if available != 2 || online != 1 {
		t.Fatalf("expected available=2 online=1, got available=%d online=%d", available, online)
	}
}

func TestProviderHealthCheckerSkipsFreshOnlineUntilInterval(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"m1"}]}`))
	}))
	defer srv.Close()

	cfg := config.NewDefaultServerConfig()
	cfg.Providers = []config.ProviderConfig{{
		Name:           "demo",
		BaseURL:        srv.URL,
		Enabled:        true,
		TimeoutSeconds: 2,
	}}
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	resolver := NewProviderResolver(store)
	checker := NewProviderHealthChecker(resolver, 15*time.Minute)
	now := time.Date(2026, 2, 23, 10, 0, 0, 0, time.UTC)
	checker.now = func() time.Time { return now }

	checker.checkOnce(context.Background(), false)
	checker.checkOnce(context.Background(), false)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 health call while online and fresh, got %d", got)
	}

	now = now.Add(16 * time.Minute)
	checker.checkOnce(context.Background(), false)
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected second health call after 15m cache expires, got %d", got)
	}
}

func TestProviderHealthCheckerRetriesOfflineEvery30Seconds(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "upstream down", http.StatusBadGateway)
	}))
	defer srv.Close()

	cfg := config.NewDefaultServerConfig()
	cfg.Providers = []config.ProviderConfig{{
		Name:           "demo",
		BaseURL:        srv.URL,
		Enabled:        true,
		TimeoutSeconds: 2,
	}}
	store := config.NewServerConfigStore("/tmp/non-persistent.toml", cfg)
	resolver := NewProviderResolver(store)
	checker := NewProviderHealthChecker(resolver, 15*time.Minute)
	now := time.Date(2026, 2, 23, 10, 0, 0, 0, time.UTC)
	checker.now = func() time.Time { return now }

	checker.checkOnce(context.Background(), false)
	checker.checkOnce(context.Background(), false)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected no immediate retry for offline provider, got %d", got)
	}

	now = now.Add(29 * time.Second)
	checker.checkOnce(context.Background(), false)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected still cached before 30s retry window, got %d", got)
	}

	now = now.Add(1 * time.Second)
	checker.checkOnce(context.Background(), false)
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected retry at 30s, got %d", got)
	}
}
