package proxy

import (
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lkarlslund/openai-personal-proxy/pkg/config"
)

func TestRequestIsLoopback(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.test/v1/models", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	if !requestIsLoopback(r) {
		t.Fatal("expected loopback request to be true")
	}
	r.RemoteAddr = "10.1.2.3:12345"
	if requestIsLoopback(r) {
		t.Fatal("expected non-loopback request to be false")
	}
}

func TestKeyAllowedRespectsExpiry(t *testing.T) {
	oldNow := nowUTC
	nowUTC = func() time.Time { return time.Date(2026, 2, 22, 12, 0, 0, 0, time.UTC) }
	defer func() { nowUTC = oldNow }()

	valid := config.IncomingAPIToken{
		Key:       "valid",
		ExpiresAt: "2026-02-22T13:00:00Z",
	}
	expired := config.IncomingAPIToken{
		Key:       "expired",
		ExpiresAt: "2026-02-22T11:00:00Z",
	}
	if !keyAllowed("valid", []config.IncomingAPIToken{valid, expired}, nil) {
		t.Fatal("expected valid token to be accepted")
	}
	if keyAllowed("expired", []config.IncomingAPIToken{valid, expired}, nil) {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestRequestIsTrustedNoAuthHostDockerInternal(t *testing.T) {
	oldLookup := lookupHost
	defer func() { lookupHost = oldLookup }()
	lookupHost = func(host string) ([]string, error) {
		if host == "host.docker.internal" {
			return []string{"192.168.65.2"}, nil
		}
		return nil, nil
	}

	hostDockerInternalIPs.mu.Lock()
	hostDockerInternalIPs.expires = time.Time{}
	hostDockerInternalIPs.ips = nil
	hostDockerInternalIPs.mu.Unlock()

	cfg := config.ServerConfig{
		AllowLocalhostNoAuth:          true,
		AllowHostDockerInternalNoAuth: true,
	}
	r := httptest.NewRequest("GET", "http://example.test/v1/models", nil)
	r.RemoteAddr = "192.168.65.2:41430"
	if !requestIsTrustedNoAuth(r, cfg) {
		t.Fatal("expected host.docker.internal resolved ip to be trusted")
	}

	r.RemoteAddr = net.JoinHostPort("10.1.2.3", "41430")
	if requestIsTrustedNoAuth(r, cfg) {
		t.Fatal("expected non-loopback non-docker-internal ip to be rejected")
	}
}
