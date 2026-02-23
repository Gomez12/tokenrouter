package proxy

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/openai-personal-proxy/pkg/config"
)

var lookupHost = net.LookupHost

type dockerInternalCache struct {
	mu      sync.Mutex
	expires time.Time
	ips     []net.IP
}

var hostDockerInternalIPs dockerInternalCache

func bearerToken(h http.Header) string {
	auth := h.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func keyAllowed(token string, tokens []config.IncomingAPIToken, allowed []string) bool {
	if token == "" {
		return false
	}
	for _, t := range tokens {
		if token != t.Key {
			continue
		}
		if strings.TrimSpace(t.ExpiresAt) == "" {
			return true
		}
		expiresAt, err := parseRFC3339(t.ExpiresAt)
		if err != nil {
			continue
		}
		return nowUTC().Before(expiresAt)
	}
	for _, k := range allowed {
		if token == k {
			return true
		}
	}
	return false
}

func requestIsLoopback(r *http.Request) bool {
	return hostIsLoopback(remoteHost(r))
}

func requestIsTrustedNoAuth(r *http.Request, cfg config.ServerConfig) bool {
	host := remoteHost(r)
	if hostIsLoopback(host) {
		return true
	}
	if cfg.AllowHostDockerInternalNoAuth && hostIsHostDockerInternal(host) {
		return true
	}
	return false
}

func remoteHost(r *http.Request) string {
	host := strings.TrimSpace(r.RemoteAddr)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

func hostIsLoopback(host string) bool {
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(host, "localhost")
}

func hostIsHostDockerInternal(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "host.docker.internal") {
		return true
	}
	remoteIP := net.ParseIP(host)
	if remoteIP == nil {
		return false
	}
	for _, ip := range cachedHostDockerInternalIPs() {
		if ip.Equal(remoteIP) {
			return true
		}
	}
	return false
}

func cachedHostDockerInternalIPs() []net.IP {
	now := nowUTC()
	hostDockerInternalIPs.mu.Lock()
	defer hostDockerInternalIPs.mu.Unlock()
	if now.Before(hostDockerInternalIPs.expires) && len(hostDockerInternalIPs.ips) > 0 {
		return append([]net.IP(nil), hostDockerInternalIPs.ips...)
	}
	raw, err := lookupHost("host.docker.internal")
	if err != nil {
		hostDockerInternalIPs.expires = now.Add(30 * time.Second)
		hostDockerInternalIPs.ips = nil
		return nil
	}
	ips := make([]net.IP, 0, len(raw))
	for _, s := range raw {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			ips = append(ips, ip)
		}
	}
	hostDockerInternalIPs.expires = now.Add(5 * time.Minute)
	hostDockerInternalIPs.ips = ips
	return append([]net.IP(nil), ips...)
}

var nowUTC = func() time.Time { return time.Now().UTC() }

func parseRFC3339(v string) (time.Time, error) {
	return time.Parse(time.RFC3339, strings.TrimSpace(v))
}
