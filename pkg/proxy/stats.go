package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const usageBucketSize = 5 * time.Minute
const usagePersistInterval = 5 * time.Second
const usageRetention = 30 * 24 * time.Hour
const maxSummaryTPS = 2000.0

type UsageEvent struct {
	Timestamp      time.Time `json:"timestamp"`
	Provider       string    `json:"provider"`
	Model          string    `json:"model"`
	ClientType     string    `json:"client_type,omitempty"`
	ClientIP       string    `json:"client_ip,omitempty"`
	APIKeyName     string    `json:"api_key_name,omitempty"`
	PromptTokens   int       `json:"prompt_tokens"`
	CompletionToks int       `json:"completion_tokens"`
	TotalTokens    int       `json:"total_tokens"`
	LatencyMS      int64     `json:"latency_ms"`
	PromptTPS      float64   `json:"prompt_tps"`
	GenTPS         float64   `json:"gen_tps"`
}

type StatsSummary struct {
	PeriodSeconds         int64                            `json:"period_seconds"`
	Requests              int                              `json:"requests"`
	PromptTokens          int                              `json:"prompt_tokens"`
	CompletionTokens      int                              `json:"completion_tokens"`
	TotalTokens           int                              `json:"total_tokens"`
	AvgLatencyMS          float64                          `json:"avg_latency_ms"`
	AvgPromptTPS          float64                          `json:"avg_prompt_tps"`
	AvgGenerationTPS      float64                          `json:"avg_generation_tps"`
	ProvidersAvailable    int                              `json:"providers_available,omitempty"`
	ProvidersOnline       int                              `json:"providers_online,omitempty"`
	ProviderQuotas        map[string]ProviderQuotaSnapshot `json:"provider_quotas,omitempty"`
	RequestsPerProvider   map[string]int                   `json:"requests_per_provider"`
	RequestsPerModel      map[string]int                   `json:"requests_per_model"`
	RequestsPerClientType map[string]int                   `json:"requests_per_client_type,omitempty"`
	RequestsPerClientIP   map[string]int                   `json:"requests_per_client_ip,omitempty"`
	RequestsPerAPIKeyName map[string]int                   `json:"requests_per_api_key_name,omitempty"`
	Buckets               []UsageBucket                    `json:"buckets,omitempty"`
}

type ProviderQuotaSnapshot struct {
	Provider     string                `json:"provider"`
	ProviderType string                `json:"provider_type,omitempty"`
	DisplayName  string                `json:"display_name,omitempty"`
	Reader       string                `json:"reader,omitempty"`
	PlanType     string                `json:"plan_type,omitempty"`
	LeftPercent  float64               `json:"left_percent,omitempty"`
	ResetAt      string                `json:"reset_at,omitempty"`
	Metrics      []ProviderQuotaMetric `json:"metrics,omitempty"`
	CheckedAt    string                `json:"checked_at,omitempty"`
	Status       string                `json:"status"`
	Error        string                `json:"error,omitempty"`
}

type ProviderQuotaMetric struct {
	Key            string  `json:"key,omitempty"`
	MeteredFeature string  `json:"metered_feature,omitempty"`
	Window         string  `json:"window,omitempty"`
	WindowSeconds  int64   `json:"window_seconds,omitempty"`
	LeftPercent    float64 `json:"left_percent,omitempty"`
	ResetAt        string  `json:"reset_at,omitempty"`
}

type UsageBucket struct {
	StartAt          time.Time `json:"start_at"`
	Provider         string    `json:"provider"`
	Model            string    `json:"model"`
	ClientType       string    `json:"client_type,omitempty"`
	ClientIP         string    `json:"client_ip,omitempty"`
	APIKeyName       string    `json:"api_key_name,omitempty"`
	Requests         int       `json:"requests"`
	PromptTokens     int       `json:"prompt_tokens"`
	CompletionTokens int       `json:"completion_tokens"`
	TotalTokens      int       `json:"total_tokens"`
	LatencyMSSum     int64     `json:"latency_ms_sum"`
	PromptTPSSum     float64   `json:"prompt_tps_sum"`
	GenerationTPSSum float64   `json:"generation_tps_sum"`
}

type usageStatsFile struct {
	Version int           `json:"version"`
	Buckets []UsageBucket `json:"buckets"`
}

type StatsStore struct {
	mu       sync.RWMutex
	buckets  map[string]*UsageBucket
	maxKeep  int
	path     string
	dirty    bool
	lastSave time.Time
}

func NewStatsStore(maxKeep int) *StatsStore {
	return newStatsStore(maxKeep, "")
}

func NewPersistentStatsStore(maxKeep int, path string) *StatsStore {
	return newStatsStore(maxKeep, path)
}

func newStatsStore(maxKeep int, path string) *StatsStore {
	if maxKeep <= 0 {
		maxKeep = 10000
	}
	s := &StatsStore{
		buckets: map[string]*UsageBucket{},
		maxKeep: maxKeep,
		path:    strings.TrimSpace(path),
	}
	if s.path != "" {
		s.load()
	}
	return s
}

func (s *StatsStore) Add(evt UsageEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := evt.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	start := ts.UTC().Truncate(usageBucketSize)
	clientType := strings.TrimSpace(evt.ClientType)
	clientIP := strings.TrimSpace(evt.ClientIP)
	apiKeyName := strings.TrimSpace(evt.APIKeyName)
	key := bucketKey(start, evt.Provider, evt.Model, clientType, clientIP, apiKeyName)
	b, ok := s.buckets[key]
	if !ok {
		b = &UsageBucket{
			StartAt:    start,
			Provider:   evt.Provider,
			Model:      evt.Model,
			ClientType: clientType,
			ClientIP:   clientIP,
			APIKeyName: apiKeyName,
		}
		s.buckets[key] = b
	}
	b.Requests++
	b.PromptTokens += evt.PromptTokens
	b.CompletionTokens += evt.CompletionToks
	b.TotalTokens += evt.TotalTokens
	b.LatencyMSSum += evt.LatencyMS
	b.PromptTPSSum += evt.PromptTPS
	b.GenerationTPSSum += evt.GenTPS
	s.pruneLocked()
	s.dirty = true
	if s.path != "" && time.Since(s.lastSave) >= usagePersistInterval {
		s.saveLocked()
	}
}

func (s *StatsStore) Summary(period time.Duration) StatsSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cutoff := time.Now().Add(-period)
	summary := StatsSummary{
		PeriodSeconds:         int64(period.Seconds()),
		RequestsPerProvider:   map[string]int{},
		RequestsPerModel:      map[string]int{},
		RequestsPerClientType: map[string]int{},
		RequestsPerClientIP:   map[string]int{},
		RequestsPerAPIKeyName: map[string]int{},
	}
	var (
		count            int
		prompt           int
		completion       int
		total            int
		latencySum       int64
		promptTPSSum     float64
		generationTPSSum float64
	)
	for _, b := range s.buckets {
		if b.StartAt.Add(usageBucketSize).Before(cutoff) {
			continue
		}
		bucket := *b
		if bucket.Requests > 0 {
			avgPrompt := bucket.PromptTPSSum / float64(bucket.Requests)
			avgGen := bucket.GenerationTPSSum / float64(bucket.Requests)
			if avgPrompt > maxSummaryTPS {
				bucket.PromptTPSSum = maxSummaryTPS * float64(bucket.Requests)
			}
			if avgGen > maxSummaryTPS {
				bucket.GenerationTPSSum = maxSummaryTPS * float64(bucket.Requests)
			}
		}
		count += b.Requests
		prompt += b.PromptTokens
		completion += b.CompletionTokens
		total += b.TotalTokens
		latencySum += b.LatencyMSSum
		promptTPSSum += bucket.PromptTPSSum
		generationTPSSum += bucket.GenerationTPSSum
		summary.RequestsPerProvider[b.Provider] += b.Requests
		summary.RequestsPerModel[b.Model] += b.Requests
		if clientType := strings.TrimSpace(b.ClientType); clientType != "" {
			summary.RequestsPerClientType[clientType] += b.Requests
		}
		if clientIP := strings.TrimSpace(b.ClientIP); clientIP != "" {
			summary.RequestsPerClientIP[clientIP] += b.Requests
		}
		if keyName := strings.TrimSpace(b.APIKeyName); keyName != "" {
			summary.RequestsPerAPIKeyName[keyName] += b.Requests
		}
		summary.Buckets = append(summary.Buckets, bucket)
	}
	summary.Requests = count
	summary.PromptTokens = prompt
	summary.CompletionTokens = completion
	summary.TotalTokens = total
	sort.Slice(summary.Buckets, func(i, j int) bool {
		if summary.Buckets[i].StartAt.Equal(summary.Buckets[j].StartAt) {
			if summary.Buckets[i].Provider == summary.Buckets[j].Provider {
				if summary.Buckets[i].Model == summary.Buckets[j].Model {
					if summary.Buckets[i].ClientType == summary.Buckets[j].ClientType {
						if summary.Buckets[i].ClientIP == summary.Buckets[j].ClientIP {
							return summary.Buckets[i].APIKeyName < summary.Buckets[j].APIKeyName
						}
						return summary.Buckets[i].ClientIP < summary.Buckets[j].ClientIP
					}
					return summary.Buckets[i].ClientType < summary.Buckets[j].ClientType
				}
				return summary.Buckets[i].Model < summary.Buckets[j].Model
			}
			return summary.Buckets[i].Provider < summary.Buckets[j].Provider
		}
		return summary.Buckets[i].StartAt.Before(summary.Buckets[j].StartAt)
	})
	if count > 0 {
		summary.AvgLatencyMS = float64(latencySum) / float64(count)
		summary.AvgPromptTPS = promptTPSSum / float64(count)
		summary.AvgGenerationTPS = generationTPSSum / float64(count)
	}
	return summary
}

func bucketKey(start time.Time, provider, model, clientType, clientIP, apiKeyName string) string {
	return start.Format(time.RFC3339) + "|" + provider + "|" + model + "|" + clientType + "|" + clientIP + "|" + apiKeyName
}

func (s *StatsStore) pruneLocked() {
	if len(s.buckets) == 0 {
		return
	}
	cutoff := time.Now().Add(-usageRetention)
	for k, b := range s.buckets {
		if b.StartAt.Before(cutoff) {
			delete(s.buckets, k)
		}
	}
	if len(s.buckets) <= s.maxKeep {
		return
	}
	type kv struct {
		key string
		at  time.Time
	}
	items := make([]kv, 0, len(s.buckets))
	for k, b := range s.buckets {
		items = append(items, kv{key: k, at: b.StartAt})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].at.Before(items[j].at) })
	drop := len(items) - s.maxKeep
	for i := 0; i < drop; i++ {
		delete(s.buckets, items[i].key)
	}
}

func (s *StatsStore) load() {
	b, err := os.ReadFile(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var payload usageStatsFile
	if err := json.Unmarshal(b, &payload); err != nil {
		return
	}
	if payload.Version != 1 {
		return
	}
	for i := range payload.Buckets {
		bk := payload.Buckets[i]
		k := bucketKey(bk.StartAt, bk.Provider, bk.Model, strings.TrimSpace(bk.ClientType), strings.TrimSpace(bk.ClientIP), strings.TrimSpace(bk.APIKeyName))
		c := bk
		s.buckets[k] = &c
	}
	s.pruneLocked()
}

func (s *StatsStore) saveLocked() {
	if s.path == "" || !s.dirty {
		return
	}
	out := usageStatsFile{Version: 1, Buckets: make([]UsageBucket, 0, len(s.buckets))}
	for _, b := range s.buckets {
		out.Buckets = append(out.Buckets, *b)
	}
	sort.Slice(out.Buckets, func(i, j int) bool {
		if out.Buckets[i].StartAt.Equal(out.Buckets[j].StartAt) {
			if out.Buckets[i].Provider == out.Buckets[j].Provider {
				return out.Buckets[i].Model < out.Buckets[j].Model
			}
			return out.Buckets[i].Provider < out.Buckets[j].Provider
		}
		return out.Buckets[i].StartAt.Before(out.Buckets[j].StartAt)
	})
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return
	}
	s.lastSave = time.Now()
	s.dirty = false
}
