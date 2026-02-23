package proxy

import (
	"context"
	"net/http"
	"sync"
	"time"
)

const providerHealthCheckInterval = 15 * time.Minute
const providerHealthRetryInterval = 30 * time.Second

type ProviderHealth struct {
	Status     string
	ResponseMS int64
	ModelCount int
	CheckedAt  time.Time
}

type ProviderHealthChecker struct {
	resolver *ProviderResolver
	interval time.Duration
	retry    time.Duration
	poll     time.Duration
	now      func() time.Time

	mu      sync.RWMutex
	byName  map[string]ProviderHealth
	forceCh chan struct{}
}

func NewProviderHealthChecker(resolver *ProviderResolver, interval time.Duration) *ProviderHealthChecker {
	if interval <= 0 {
		interval = providerHealthCheckInterval
	}
	poll := providerHealthRetryInterval
	if interval > 0 && interval < poll {
		poll = interval
	}
	return &ProviderHealthChecker{
		resolver: resolver,
		interval: interval,
		retry:    providerHealthRetryInterval,
		poll:     poll,
		now:      time.Now,
		byName:   map[string]ProviderHealth{},
		forceCh:  make(chan struct{}, 1),
	}
}

func (c *ProviderHealthChecker) Run(ctx context.Context) {
	if c == nil || c.resolver == nil {
		return
	}
	c.checkOnce(ctx, false)
	t := time.NewTicker(c.poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.checkOnce(ctx, false)
		case <-c.forceCh:
			c.checkOnce(ctx, true)
		}
	}
}

func (c *ProviderHealthChecker) Trigger() {
	if c == nil {
		return
	}
	select {
	case c.forceCh <- struct{}{}:
	default:
	}
}

func (c *ProviderHealthChecker) Snapshot(name string) (ProviderHealth, bool) {
	if c == nil {
		return ProviderHealth{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.byName[name]
	return v, ok
}

func (c *ProviderHealthChecker) RecordProxyResult(provider string, latency time.Duration, statusCode int, reqErr error) {
	if c == nil || provider == "" {
		return
	}
	snap := ProviderHealth{
		Status:     "online",
		ResponseMS: latency.Milliseconds(),
		CheckedAt:  c.now().UTC(),
	}
	if reqErr != nil {
		snap.Status = "offline"
	} else if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		snap.Status = "auth problem"
	}

	c.mu.Lock()
	if prev, ok := c.byName[provider]; ok {
		snap.ModelCount = prev.ModelCount
	}
	c.byName[provider] = snap
	c.mu.Unlock()
}

func (c *ProviderHealthChecker) AvailabilitySummary(providers []string) (available int, online int) {
	if c == nil {
		return len(providers), 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, name := range providers {
		available++
		snap, ok := c.byName[name]
		if ok && snap.Status == "online" {
			online++
		}
	}
	return available, online
}

func (c *ProviderHealthChecker) shouldCheck(name string, now time.Time, force bool) bool {
	if force {
		return true
	}
	c.mu.RLock()
	snap, ok := c.byName[name]
	c.mu.RUnlock()
	if !ok || snap.CheckedAt.IsZero() {
		return true
	}
	age := now.Sub(snap.CheckedAt)
	if age < 0 {
		age = 0
	}
	if snap.Status == "online" {
		return age >= c.interval
	}
	return age >= c.retry
}

func (c *ProviderHealthChecker) checkOnce(parent context.Context, force bool) {
	providers := c.resolver.ListProviders()
	now := c.now()
	active := make(map[string]struct{}, len(providers))
	for _, p := range providers {
		active[p.Name] = struct{}{}
		if !c.shouldCheck(p.Name, now, force) {
			continue
		}
		if c.resolver != nil {
			p = refreshOAuthTokenForProvider(parent, c.resolver.store, p)
		}
		start := c.now()
		timeout := p.TimeoutSeconds
		if timeout <= 0 {
			timeout = 60
		}
		ctx := parent
		cancel := func() {}
		if parent != nil {
			ctx, cancel = context.WithTimeout(parent, time.Duration(timeout)*time.Second)
		}
		models, err := NewProviderClient(p).ListModels(ctx)
		cancel()
		snap := ProviderHealth{
			Status:     "online",
			ResponseMS: c.now().Sub(start).Milliseconds(),
			ModelCount: len(models),
			CheckedAt:  c.now().UTC(),
		}
		if err != nil {
			snap.Status = "offline"
			if IsProviderBlocked(err) {
				snap.Status = "blocked"
			} else if IsProviderAuthError(err) {
				snap.Status = "auth problem"
			}
		}
		c.mu.Lock()
		c.byName[p.Name] = snap
		c.mu.Unlock()
	}
	c.mu.Lock()
	for name := range c.byName {
		if _, ok := active[name]; !ok {
			delete(c.byName, name)
		}
	}
	c.mu.Unlock()
}
