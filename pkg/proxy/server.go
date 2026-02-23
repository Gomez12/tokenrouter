package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/lkarlslund/openai-personal-proxy/pkg/cache"
	"github.com/lkarlslund/openai-personal-proxy/pkg/config"
	"github.com/lkarlslund/openai-personal-proxy/pkg/pricing"
	"golang.org/x/crypto/acme/autocert"
)

type Server struct {
	store                 *config.ServerConfigStore
	resolver              *ProviderResolver
	stats                 *StatsStore
	pricing               *pricing.Manager
	providerHealthChecker *ProviderHealthChecker
	adminHandler          *AdminHandler
	httpServer            *http.Server
	modelsCachePath       string
	modelsCached          atomic.Pointer[[]ModelCard]
	activeProxyRequests   atomic.Int64
	draining              atomic.Bool
}

func NewServer(configPath string, cfg *config.ServerConfig) (*Server, error) {
	store := config.NewServerConfigStore(configPath, cfg)
	resolver := NewProviderResolver(store)
	stats := NewPersistentStatsStore(10000, config.DefaultUsageStatsPath())

	s := &Server{
		store:           store,
		resolver:        resolver,
		stats:           stats,
		modelsCachePath: config.DefaultModelsCachePath(),
	}
	s.loadModelsCacheFromDisk()
	pricingMgr, err := pricing.NewManager(config.DefaultPricingCachePath())
	if err != nil {
		return nil, fmt.Errorf("init pricing manager: %w", err)
	}
	pricingMgr.SetProviders(resolver.ListProviders())
	s.pricing = pricingMgr
	s.providerHealthChecker = NewProviderHealthChecker(resolver, providerHealthCheckInterval)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(s.proxyRequestLifecycleMiddleware)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/admin", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	r.Route("/v1", func(v1 chi.Router) {
		v1.Use(s.authAPIMiddleware)
		v1.Get("/models", s.handleModels)
		v1.Post("/chat/completions", s.proxyHandler)
		v1.Post("/completions", s.proxyHandler)
		v1.Post("/embeddings", s.proxyHandler)
		v1.Post("/responses", s.proxyHandler)
	})

	instanceID := fmt.Sprintf("%d-%d", time.Now().UTC().UnixNano(), os.Getpid())
	adminHandler := NewAdminHandler(store, stats, resolver, pricingMgr, s.providerHealthChecker, instanceID)
	s.adminHandler = adminHandler
	adminHandler.RegisterRoutes(r)

	s.httpServer = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}

	return s, nil
}

func (s *Server) Run(ctx context.Context) error {
	cfg := s.store.Snapshot()
	errCh := make(chan error, 2)
	go s.providerHealthChecker.Run(ctx)

	if cfg.TLS.Enabled {
		mgr := &autocert.Manager{
			Cache:      autocert.DirCache(cfg.TLS.CacheDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.TLS.Domain),
			Email:      cfg.TLS.Email,
		}

		httpsSrv := *s.httpServer
		httpsSrv.Addr = ":443"
		httpsSrv.TLSConfig = &tls.Config{GetCertificate: mgr.GetCertificate, MinVersion: tls.VersionTLS12}

		httpChallenge := &http.Server{
			Addr:              ":80",
			Handler:           mgr.HTTPHandler(http.HandlerFunc(redirectHTTPS)),
			ReadHeaderTimeout: 10 * time.Second,
		}

		go func() {
			log.Printf("http challenge/redirect listening on :80")
			if err := httpChallenge.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("http challenge server: %w", err)
			}
		}()

		go func() {
			log.Printf("https listening on :443 for %s", cfg.TLS.Domain)
			if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("https server: %w", err)
			}
		}()

		<-ctx.Done()
		s.draining.Store(true)
		s.waitForProxyIdle(ctx)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpChallenge.Shutdown(shutdownCtx)
		_ = httpsSrv.Shutdown(shutdownCtx)
		return firstErr(errCh)
	}

	go func() {
		log.Printf("proxy listening on %s", cfg.ListenAddr)
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("proxy server: %w", err)
		}
	}()

	<-ctx.Done()
	s.draining.Store(true)
	s.waitForProxyIdle(ctx)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = s.httpServer.Shutdown(shutdownCtx)
	return firstErr(errCh)
}

func redirectHTTPS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
}

func (s *Server) proxyRequestLifecycleMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isProxyReq := strings.HasPrefix(r.URL.Path, "/v1/")
		if isProxyReq && s.draining.Load() {
			w.Header().Set("Retry-After", "3")
			http.Error(w, "server shutting down", http.StatusServiceUnavailable)
			return
		}
		if isProxyReq {
			s.activeProxyRequests.Add(1)
			defer s.activeProxyRequests.Add(-1)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) waitForProxyIdle(ctx context.Context) {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	lastLog := time.Time{}
	for {
		active := s.activeProxyRequests.Load()
		if active <= 0 {
			log.Printf("shutdown: proxy idle")
			return
		}
		if lastLog.IsZero() || time.Since(lastLog) >= time.Second {
			log.Printf("shutdown: waiting for %d active proxy request(s)", active)
			lastLog = time.Now()
		}
		select {
		case <-ctx.Done():
		case <-t.C:
		}
	}
}

func (s *Server) authAPIMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := s.store.Snapshot()
		if cfg.AllowLocalhostNoAuth && requestIsTrustedNoAuth(r, cfg) {
			next.ServeHTTP(w, r)
			return
		}
		if !keyAllowed(bearerToken(r.Header), cfg.IncomingTokens, cfg.IncomingAPIKeys) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	models, err := s.resolver.DiscoverModels(r.Context())
	if err != nil {
		if cached := s.modelsCached.Load(); cached != nil {
			models = *cached
		} else {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	} else {
		s.modelsCached.Store(&models)
		s.saveModelsCacheToDisk(models)
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": models})
}

func (s *Server) loadModelsCacheFromDisk() {
	if s == nil || strings.TrimSpace(s.modelsCachePath) == "" {
		return
	}
	var models []ModelCard
	if err := cache.LoadJSON(s.modelsCachePath, &models); err != nil {
		return
	}
	if len(models) == 0 {
		return
	}
	s.modelsCached.Store(&models)
}

func (s *Server) saveModelsCacheToDisk(models []ModelCard) {
	if s == nil || strings.TrimSpace(s.modelsCachePath) == "" {
		return
	}
	cp := append([]ModelCard(nil), models...)
	if len(cp) == 0 {
		return
	}
	_ = cache.SaveJSON(s.modelsCachePath, cp)
}

func (s *Server) proxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	model, mutatedBody, provider, upstreamModel, stream, err := s.prepareUpstreamRequest(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	clientMeta := extractClientUsageMeta(r, s.store.Snapshot())

	start := time.Now()
	if stream {
		statusCode, upstreamHeader, usage, initialLatency, err := s.forwardStreamingRequest(r.Context(), provider, r.URL.Path, mutatedBody, w)
		latency := time.Since(start)
		if err != nil {
			s.providerHealthChecker.RecordProxyResult(provider.Name, latency, statusCode, err)
			if statusCode == 0 {
				http.Error(w, err.Error(), http.StatusBadGateway)
			}
			return
		}
		s.providerHealthChecker.RecordProxyResult(provider.Name, latency, statusCode, nil)
		if statusCode >= 200 && statusCode <= 299 && s.adminHandler != nil {
			s.adminHandler.RecordQuotaFromResponse(provider, upstreamHeader)
		}
		if usage.TotalTokens == 0 {
			usage.PromptTokens = estimatePromptTokensFromRequest(body)
			if usage.CompletionTokens == 0 {
				usage.CompletionTokens = usage.EstimatedCompletionTokens
			}
			usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
		}
		promptTPS, genTPS := computePromptAndGenerationTPS(usage.PromptTokens, usage.CompletionTokens, initialLatency, latency)
		s.recordUsageMeasured(provider.Name, model, upstreamModel, statusCode, latency, usage.PromptTokens, usage.CompletionTokens, usage.TotalTokens, promptTPS, genTPS, clientMeta)
		return
	}

	respBody, statusCode, header, initialLatency, err := s.forwardRequest(r.Context(), provider, r.URL.Path, mutatedBody)
	latency := time.Since(start)
	if err != nil {
		s.providerHealthChecker.RecordProxyResult(provider.Name, latency, 0, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.providerHealthChecker.RecordProxyResult(provider.Name, latency, statusCode, nil)
	if statusCode >= 200 && statusCode <= 299 && s.adminHandler != nil {
		s.adminHandler.RecordQuotaFromResponse(provider, header)
	}

	for k, vals := range header {
		if strings.EqualFold(k, "content-length") {
			continue
		}
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(statusCode)
	_, _ = w.Write(respBody)

	promptTokens, completionTokens, totalTokens := parseUsageTokens(respBody)
	if totalTokens == 0 {
		promptTokens = estimatePromptTokensFromRequest(body)
		completionTokens = estimateCompletionTokensFromResponse(respBody)
		totalTokens = promptTokens + completionTokens
	}
	promptTPS, genTPS := computePromptAndGenerationTPS(promptTokens, completionTokens, initialLatency, latency)
	s.recordUsageMeasured(provider.Name, model, upstreamModel, statusCode, latency, promptTokens, completionTokens, totalTokens, promptTPS, genTPS, clientMeta)
}

func (s *Server) prepareUpstreamRequest(body []byte) (incomingModel string, outBody []byte, provider config.ProviderConfig, upstreamModel string, stream bool, err error) {
	if len(body) == 0 {
		return "", nil, config.ProviderConfig{}, "", false, fmt.Errorf("request body required")
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", nil, config.ProviderConfig{}, "", false, fmt.Errorf("invalid json")
	}
	modelAny, ok := payload["model"]
	if !ok {
		return "", nil, config.ProviderConfig{}, "", false, fmt.Errorf("model is required")
	}
	model, ok := modelAny.(string)
	if !ok || strings.TrimSpace(model) == "" {
		return "", nil, config.ProviderConfig{}, "", false, fmt.Errorf("model must be a non-empty string")
	}
	stream, _ = payload["stream"].(bool)
	provider, upstreamModel, err = s.resolver.Resolve(model)
	if err != nil {
		return "", nil, config.ProviderConfig{}, "", false, err
	}
	payload["model"] = upstreamModel
	outBody, err = json.Marshal(payload)
	if err != nil {
		return "", nil, config.ProviderConfig{}, "", false, fmt.Errorf("encode json: %w", err)
	}
	return model, outBody, provider, upstreamModel, stream, nil
}

func (s *Server) forwardRequest(ctx context.Context, provider config.ProviderConfig, requestPath string, body []byte) ([]byte, int, http.Header, time.Duration, error) {
	provider = s.ensureOAuthTokenFresh(ctx, provider)
	u, err := url.Parse(strings.TrimRight(provider.BaseURL, "/"))
	if err != nil {
		return nil, 0, nil, 0, fmt.Errorf("invalid provider base_url: %w", err)
	}
	if isOpenAICodexProvider(provider) && requestPath == "/v1/responses" {
		requestPath = "/codex/responses"
	}
	u.Path = joinProviderPath(u.Path, requestPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if provider.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+provider.APIKey)
	} else if strings.TrimSpace(provider.AuthToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(provider.AuthToken))
	}
	if isOpenAICodexProvider(provider) {
		req.Header.Set("OpenAI-Beta", "responses=experimental")
		req.Header.Set("originator", "codex_cli_rs")
		if strings.TrimSpace(provider.AccountID) != "" {
			req.Header.Set("chatgpt-account-id", strings.TrimSpace(provider.AccountID))
		}
	}

	cli := &http.Client{Timeout: time.Duration(provider.TimeoutSeconds) * time.Second}
	upstreamStart := time.Now()
	resp, err := cli.Do(req)
	if err != nil {
		return nil, 0, nil, 0, err
	}
	defer resp.Body.Close()
	initialLatency := time.Since(upstreamStart)
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, 0, nil, initialLatency, err
	}
	return b, resp.StatusCode, resp.Header.Clone(), initialLatency, nil
}

type usageTokenCounts struct {
	PromptTokens              int
	CompletionTokens          int
	TotalTokens               int
	EstimatedCompletionTokens int
}

type clientUsageMeta struct {
	ClientType string
	ClientIP   string
	APIKeyName string
}

func (s *Server) forwardStreamingRequest(ctx context.Context, provider config.ProviderConfig, requestPath string, body []byte, w http.ResponseWriter) (int, http.Header, usageTokenCounts, time.Duration, error) {
	provider = s.ensureOAuthTokenFresh(ctx, provider)
	u, err := url.Parse(strings.TrimRight(provider.BaseURL, "/"))
	if err != nil {
		return 0, nil, usageTokenCounts{}, 0, fmt.Errorf("invalid provider base_url: %w", err)
	}
	if isOpenAICodexProvider(provider) && requestPath == "/v1/responses" {
		requestPath = "/codex/responses"
	}
	u.Path = joinProviderPath(u.Path, requestPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, nil, usageTokenCounts{}, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if provider.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+provider.APIKey)
	} else if strings.TrimSpace(provider.AuthToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(provider.AuthToken))
	}
	if isOpenAICodexProvider(provider) {
		req.Header.Set("OpenAI-Beta", "responses=experimental")
		req.Header.Set("originator", "codex_cli_rs")
		if strings.TrimSpace(provider.AccountID) != "" {
			req.Header.Set("chatgpt-account-id", strings.TrimSpace(provider.AccountID))
		}
	}

	cli := &http.Client{Timeout: time.Duration(provider.TimeoutSeconds) * time.Second}
	upstreamStart := time.Now()
	resp, err := cli.Do(req)
	if err != nil {
		return 0, nil, usageTokenCounts{}, 0, err
	}
	defer resp.Body.Close()
	initialLatency := time.Since(upstreamStart)
	firstChunkLatency := time.Duration(0)
	upstreamHeader := resp.Header.Clone()

	for k, vals := range resp.Header {
		if strings.EqualFold(k, "content-length") {
			continue
		}
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	parser := newSSEUsageParser()
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if firstChunkLatency <= 0 {
				firstChunkLatency = time.Since(upstreamStart)
			}
			parser.Consume(buf[:n])
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				if firstChunkLatency > 0 {
					initialLatency = firstChunkLatency
				}
				return resp.StatusCode, upstreamHeader, parser.Usage(), initialLatency, writeErr
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if errors.Is(readErr, io.EOF) {
			if firstChunkLatency > 0 {
				initialLatency = firstChunkLatency
			}
			return resp.StatusCode, upstreamHeader, parser.Usage(), initialLatency, nil
		}
		if readErr != nil {
			if firstChunkLatency > 0 {
				initialLatency = firstChunkLatency
			}
			return resp.StatusCode, upstreamHeader, parser.Usage(), initialLatency, readErr
		}
	}
}

func isOpenAICodexProvider(provider config.ProviderConfig) bool {
	base := strings.TrimSpace(provider.BaseURL)
	if base == "" {
		return false
	}
	u, err := url.Parse(base)
	if err != nil {
		baseLower := strings.ToLower(base)
		return strings.Contains(baseLower, "chatgpt.com/backend-api") || strings.Contains(baseLower, "/backend-api")
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	pathLower := strings.ToLower(strings.Trim(strings.TrimSpace(u.Path), "/"))
	return host == "chatgpt.com" || strings.Contains(pathLower, "backend-api")
}

func (s *Server) ensureOAuthTokenFresh(ctx context.Context, provider config.ProviderConfig) config.ProviderConfig {
	return refreshOAuthTokenForProvider(ctx, s.store, provider)
}

func (s *Server) recordUsage(providerName, incomingModel, upstreamModel string, status int, latency time.Duration, responseBody []byte) {
	if status < 200 || status > 299 {
		return
	}
	promptTokens, completionTokens, totalTokens := parseUsageTokens(responseBody)
	s.recordUsageWithTokens(providerName, incomingModel, upstreamModel, status, latency, promptTokens, completionTokens, totalTokens)
}

func (s *Server) recordUsageWithTokens(providerName, incomingModel, upstreamModel string, status int, latency time.Duration, promptTokens int, completionTokens int, totalTokens int) {
	promptTPS, genTPS := computePromptAndGenerationTPS(promptTokens, completionTokens, latency, latency)
	s.recordUsageMeasured(providerName, incomingModel, upstreamModel, status, latency, promptTokens, completionTokens, totalTokens, promptTPS, genTPS, clientUsageMeta{})
}

func (s *Server) recordUsageMeasured(providerName, incomingModel, upstreamModel string, status int, latency time.Duration, promptTokens int, completionTokens int, totalTokens int, promptTPS float64, genTPS float64, meta clientUsageMeta) {
	if status < 200 || status > 299 {
		return
	}
	s.stats.Add(UsageEvent{
		Timestamp:      time.Now(),
		Provider:       providerName,
		Model:          incomingModel,
		ClientType:     strings.TrimSpace(meta.ClientType),
		ClientIP:       strings.TrimSpace(meta.ClientIP),
		APIKeyName:     strings.TrimSpace(meta.APIKeyName),
		PromptTokens:   promptTokens,
		CompletionToks: completionTokens,
		TotalTokens:    totalTokens,
		LatencyMS:      latency.Milliseconds(),
		PromptTPS:      promptTPS,
		GenTPS:         genTPS,
	})
	_ = upstreamModel
}

func parseUsageTokens(responseBody []byte) (promptTokens int, completionTokens int, totalTokens int) {
	if len(responseBody) == 0 {
		return 0, 0, 0
	}
	var payload any
	if err := json.Unmarshal(responseBody, &payload); err != nil {
		return 0, 0, 0
	}
	return findUsageTokens(payload)
}

type sseUsageParser struct {
	pending []byte
	usage   usageTokenCounts
}

func newSSEUsageParser() *sseUsageParser {
	return &sseUsageParser{pending: make([]byte, 0, 1024)}
}

func (p *sseUsageParser) Consume(chunk []byte) {
	if len(chunk) == 0 {
		return
	}
	p.pending = append(p.pending, chunk...)
	for {
		idx := bytes.IndexByte(p.pending, '\n')
		if idx < 0 {
			return
		}
		line := strings.TrimSpace(string(p.pending[:idx]))
		p.pending = p.pending[idx+1:]
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}
		prompt, completion, total := parseUsageTokens([]byte(data))
		p.merge(prompt, completion, total)
		if p.usage.TotalTokens == 0 {
			p.usage.EstimatedCompletionTokens += estimateCompletionTokensFromResponse([]byte(data))
		}
	}
}

func (p *sseUsageParser) Usage() usageTokenCounts {
	return p.usage
}

func (p *sseUsageParser) merge(prompt int, completion int, total int) {
	if total > p.usage.TotalTokens {
		p.usage.PromptTokens = prompt
		p.usage.CompletionTokens = completion
		p.usage.TotalTokens = total
		return
	}
	if p.usage.TotalTokens == 0 && (prompt > 0 || completion > 0) {
		p.usage.PromptTokens = prompt
		p.usage.CompletionTokens = completion
		p.usage.TotalTokens = prompt + completion
	}
}

func findUsageTokens(payload any) (promptTokens int, completionTokens int, totalTokens int) {
	bestTotal := 0
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			p, c, t, ok := parseUsageObject(x)
			if ok {
				score := t
				if score == 0 {
					score = p + c
				}
				if score > bestTotal {
					promptTokens, completionTokens, totalTokens = p, c, t
					bestTotal = score
				}
			}
			for _, vv := range x {
				walk(vv)
			}
		case []any:
			for _, vv := range x {
				walk(vv)
			}
		}
	}
	walk(payload)
	if totalTokens == 0 {
		totalTokens = promptTokens + completionTokens
	}
	return promptTokens, completionTokens, totalTokens
}

func parseUsageObject(m map[string]any) (prompt int, completion int, total int, ok bool) {
	usageRaw, hasUsage := m["usage"]
	if hasUsage {
		if usageMap, mapOK := usageRaw.(map[string]any); mapOK {
			return parseUsageFields(usageMap)
		}
	}
	return parseUsageFields(m)
}

func parseUsageFields(m map[string]any) (prompt int, completion int, total int, ok bool) {
	prompt = int(firstFloat(m, "prompt_tokens", "input_tokens"))
	completion = int(firstFloat(m, "completion_tokens", "output_tokens"))
	total = int(firstFloat(m, "total_tokens"))
	if prompt == 0 && completion == 0 && total == 0 {
		return 0, 0, 0, false
	}
	if total == 0 {
		total = prompt + completion
	}
	return prompt, completion, total, true
}

func firstFloat(m map[string]any, keys ...string) float64 {
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch n := v.(type) {
		case float64:
			return n
		case int:
			return float64(n)
		case int64:
			return float64(n)
		case json.Number:
			if f, err := n.Float64(); err == nil {
				return f
			}
		}
	}
	return 0
}

func extractClientUsageMeta(r *http.Request, cfg config.ServerConfig) clientUsageMeta {
	token := strings.TrimSpace(bearerToken(r.Header))
	return clientUsageMeta{
		ClientType: classifyClientType(r.Header.Get("User-Agent")),
		ClientIP:   requestClientIP(r),
		APIKeyName: resolveIncomingTokenName(token, cfg),
	}
}

func requestClientIP(r *http.Request) string {
	host := strings.TrimSpace(r.RemoteAddr)
	if host == "" {
		return ""
	}
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		return strings.TrimSpace(parsed)
	}
	return host
}

func classifyClientType(userAgent string) string {
	ua := strings.ToLower(strings.TrimSpace(userAgent))
	if ua == "" {
		return "unknown"
	}
	switch {
	case strings.Contains(ua, "openai-python"):
		return "openai-python"
	case strings.Contains(ua, "openai-node"):
		return "openai-node"
	case strings.Contains(ua, "openai-go"):
		return "openai-go"
	case strings.Contains(ua, "curl/"):
		return "curl"
	case strings.Contains(ua, "python-requests"), strings.Contains(ua, "python-httpx"), strings.Contains(ua, "python"):
		return "python"
	case strings.Contains(ua, "node"), strings.Contains(ua, "undici"), strings.Contains(ua, "axios"):
		return "nodejs"
	case strings.Contains(ua, "go-http-client"):
		return "go-http-client"
	case strings.Contains(ua, "mozilla/"):
		return "browser"
	default:
		return "other"
	}
}

func resolveIncomingTokenName(token string, cfg config.ServerConfig) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	for _, t := range cfg.IncomingTokens {
		if token != strings.TrimSpace(t.Key) {
			continue
		}
		expiresAt := strings.TrimSpace(t.ExpiresAt)
		if expiresAt != "" {
			ts, err := parseRFC3339(expiresAt)
			if err != nil || !nowUTC().Before(ts) {
				return ""
			}
		}
		name := strings.TrimSpace(t.Name)
		if name != "" {
			return name
		}
		return strings.TrimSpace(t.ID)
	}
	return ""
}

func computePromptAndGenerationTPS(promptTokens int, completionTokens int, initialLatency time.Duration, totalLatency time.Duration) (float64, float64) {
	const (
		minPhaseDuration = 250 * time.Millisecond
		maxMeasuredTPS   = 2000.0
	)
	if totalLatency <= 0 {
		totalLatency = time.Millisecond
	}
	if initialLatency <= 0 || initialLatency > totalLatency {
		initialLatency = totalLatency
	}
	promptSeconds := initialLatency.Seconds()
	if promptSeconds <= 0 {
		promptSeconds = 0.001
	}
	genDuration := totalLatency - initialLatency
	if genDuration <= 0 {
		genDuration = totalLatency
	}
	genSeconds := genDuration.Seconds()
	if genSeconds <= 0 {
		genSeconds = 0.001
	}
	promptTPS := 0.0
	genTPS := 0.0
	if promptTokens > 0 {
		promptTPS = float64(promptTokens) / promptSeconds
	}
	if promptTPS > maxMeasuredTPS {
		promptTPS = maxMeasuredTPS
	}
	if completionTokens > 0 {
		if genDuration < minPhaseDuration {
			genDuration = totalLatency
			if genDuration < minPhaseDuration {
				genDuration = minPhaseDuration
			}
			genSeconds = genDuration.Seconds()
		}
		genTPS = float64(completionTokens) / genSeconds
	}
	if genTPS > maxMeasuredTPS {
		genTPS = maxMeasuredTPS
	}
	return promptTPS, genTPS
}

func estimatePromptTokensFromRequest(requestBody []byte) int {
	if len(requestBody) == 0 {
		return 0
	}
	var payload any
	if err := json.Unmarshal(requestBody, &payload); err != nil {
		return 0
	}
	text := extractPromptText(payload)
	return estimateTokensFromText(text)
}

func estimateCompletionTokensFromResponse(responseBody []byte) int {
	if len(responseBody) == 0 {
		return 0
	}
	var payload any
	if err := json.Unmarshal(responseBody, &payload); err != nil {
		return 0
	}
	text := extractCompletionText(payload)
	return estimateTokensFromText(text)
}

func estimateTokensFromText(text string) int {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0
	}
	runes := utf8.RuneCountInString(text)
	if runes <= 0 {
		return 0
	}
	return (runes + 3) / 4
}

func extractPromptText(payload any) string {
	parts := make([]string, 0, 8)
	var walk func(v any, key string)
	walk = func(v any, key string) {
		switch x := v.(type) {
		case map[string]any:
			for k, vv := range x {
				lk := strings.ToLower(strings.TrimSpace(k))
				switch lk {
				case "prompt", "input", "instructions", "system", "content", "text":
					if s, ok := vv.(string); ok {
						parts = append(parts, s)
					}
				}
				walk(vv, lk)
			}
		case []any:
			for _, vv := range x {
				walk(vv, key)
			}
		case string:
			if key == "prompt" || key == "input" || key == "instructions" || key == "system" || key == "content" || key == "text" {
				parts = append(parts, x)
			}
		}
	}
	walk(payload, "")
	return strings.Join(parts, "\n")
}

func extractCompletionText(payload any) string {
	parts := make([]string, 0, 8)
	var walk func(v any, key string)
	walk = func(v any, key string) {
		switch x := v.(type) {
		case map[string]any:
			for k, vv := range x {
				lk := strings.ToLower(strings.TrimSpace(k))
				switch lk {
				case "output_text", "delta":
					if s, ok := vv.(string); ok {
						parts = append(parts, s)
					}
				case "text":
					if s, ok := vv.(string); ok && key != "input" && key != "prompt" {
						parts = append(parts, s)
					}
				case "content":
					if s, ok := vv.(string); ok && (key == "message" || key == "delta" || key == "choice" || key == "output") {
						parts = append(parts, s)
					}
				}
				walk(vv, lk)
			}
		case []any:
			for _, vv := range x {
				walk(vv, key)
			}
		}
	}
	walk(payload, "")
	return strings.Join(parts, "\n")
}

func firstErr(ch <-chan error) error {
	select {
	case err := <-ch:
		return err
	default:
		return nil
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
