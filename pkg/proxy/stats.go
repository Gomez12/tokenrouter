package proxy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lkarlslund/tokenrouter/pkg/usagedb"
)

const usageBucketSize = 5 * time.Minute
const maxSummaryTPS = 2000.0

type UsageEvent struct {
	Timestamp      time.Time `json:"timestamp"`
	Provider       string    `json:"provider"`
	Model          string    `json:"model"`
	ClientType     string    `json:"client_type,omitempty"`
	UserAgent      string    `json:"user_agent,omitempty"`
	ClientIP       string    `json:"client_ip,omitempty"`
	APIKeyName     string    `json:"api_key_name,omitempty"`
	StatusCode     int       `json:"status_code,omitempty"`
	PromptTokens   int       `json:"prompt_tokens"`
	PromptCached   int       `json:"prompt_cached_tokens,omitempty"`
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
	PromptCachedTokens    int                              `json:"prompt_cached_tokens,omitempty"`
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
	RequestsPerUserAgent  map[string]int                   `json:"requests_per_user_agent,omitempty"`
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
	LeftPercent    float64 `json:"left_percent"`
	UsedValue      float64 `json:"used_value"`
	RemainingValue float64 `json:"remaining_value"`
	LimitValue     float64 `json:"limit_value"`
	Unit           string  `json:"unit,omitempty"`
	ResetAt        string  `json:"reset_at,omitempty"`
}

type UsageBucket struct {
	StartAt          time.Time `json:"start_at"`
	SlotSeconds      int       `json:"slot_seconds,omitempty"`
	Provider         string    `json:"provider"`
	Model            string    `json:"model"`
	ClientType       string    `json:"client_type,omitempty"`
	UserAgent        string    `json:"user_agent,omitempty"`
	ClientIP         string    `json:"client_ip,omitempty"`
	APIKeyName       string    `json:"api_key_name,omitempty"`
	Requests         int       `json:"requests"`
	PromptTokens     int       `json:"prompt_tokens"`
	PromptCached     int       `json:"prompt_cached_tokens,omitempty"`
	CompletionTokens int       `json:"completion_tokens"`
	TotalTokens      int       `json:"total_tokens"`
	LatencyMSSum     int64     `json:"latency_ms_sum"`
	PromptTPSSum     float64   `json:"prompt_tps_sum"`
	GenerationTPSSum float64   `json:"generation_tps_sum"`
}

type StatsStore struct {
	db *usagedb.Store
}

func NewStatsStore(_ int) *StatsStore {
	dir := filepath.Join(os.TempDir(), "tokenrouter-usage", fmt.Sprintf("session-%d", time.Now().UTC().UnixNano()))
	return &StatsStore{db: usagedb.New(dir)}
}

func NewPersistentStatsStore(_ int, path string) *StatsStore {
	return &StatsStore{db: usagedb.New(path)}
}

func (s *StatsStore) Add(evt UsageEvent) {
	if s == nil || s.db == nil {
		return
	}
	_ = s.db.Append(usagedb.Event{
		Timestamp:      evt.Timestamp,
		Provider:       evt.Provider,
		Model:          evt.Model,
		ClientType:     strings.TrimSpace(evt.ClientType),
		UserAgent:      strings.TrimSpace(evt.UserAgent),
		ClientIP:       strings.TrimSpace(evt.ClientIP),
		APIKeyName:     strings.TrimSpace(evt.APIKeyName),
		StatusCode:     evt.StatusCode,
		PromptTokens:   evt.PromptTokens,
		PromptCached:   evt.PromptCached,
		CompletionToks: evt.CompletionToks,
		TotalTokens:    evt.TotalTokens,
		LatencyMS:      evt.LatencyMS,
		PromptTPS:      evt.PromptTPS,
		GenTPS:         evt.GenTPS,
	})
}

func (s *StatsStore) Summary(period time.Duration) StatsSummary {
	if s == nil || s.db == nil {
		return StatsSummary{PeriodSeconds: int64(period.Seconds())}
	}
	sum, err := s.db.Summary(period, time.Now().UTC())
	if err != nil {
		return StatsSummary{PeriodSeconds: int64(period.Seconds())}
	}
	out := StatsSummary{
		PeriodSeconds:         sum.PeriodSeconds,
		Requests:              sum.Requests,
		PromptTokens:          sum.PromptTokens,
		PromptCachedTokens:    sum.PromptCachedTokens,
		CompletionTokens:      sum.CompletionTokens,
		TotalTokens:           sum.TotalTokens,
		AvgLatencyMS:          sum.AvgLatencyMS,
		AvgPromptTPS:          sum.AvgPromptTPS,
		AvgGenerationTPS:      sum.AvgGenerationTPS,
		RequestsPerProvider:   sum.RequestsPerProvider,
		RequestsPerModel:      sum.RequestsPerModel,
		RequestsPerClientType: sum.RequestsPerClientType,
		RequestsPerUserAgent:  sum.RequestsPerUserAgent,
		RequestsPerClientIP:   sum.RequestsPerClientIP,
		RequestsPerAPIKeyName: sum.RequestsPerAPIKeyName,
		Buckets:               make([]UsageBucket, 0, len(sum.Buckets)),
	}
	for _, b := range sum.Buckets {
		out.Buckets = append(out.Buckets, UsageBucket{
			StartAt:          b.StartAt,
			SlotSeconds:      b.SlotSeconds,
			Provider:         b.Provider,
			Model:            b.Model,
			ClientType:       b.ClientType,
			UserAgent:        b.UserAgent,
			ClientIP:         b.ClientIP,
			APIKeyName:       b.APIKeyName,
			Requests:         b.Requests,
			PromptTokens:     b.PromptTokens,
			PromptCached:     b.PromptCached,
			CompletionTokens: b.CompletionTokens,
			TotalTokens:      b.TotalTokens,
			LatencyMSSum:     b.LatencyMSSum,
			PromptTPSSum:     b.PromptTPSSum,
			GenerationTPSSum: b.GenerationTPSSum,
		})
	}
	sort.Slice(out.Buckets, func(i, j int) bool {
		if out.Buckets[i].StartAt.Equal(out.Buckets[j].StartAt) {
			if out.Buckets[i].Provider == out.Buckets[j].Provider {
				if out.Buckets[i].Model == out.Buckets[j].Model {
					if out.Buckets[i].ClientType == out.Buckets[j].ClientType {
						if out.Buckets[i].UserAgent == out.Buckets[j].UserAgent {
							if out.Buckets[i].ClientIP == out.Buckets[j].ClientIP {
								return out.Buckets[i].APIKeyName < out.Buckets[j].APIKeyName
							}
							return out.Buckets[i].ClientIP < out.Buckets[j].ClientIP
						}
						return out.Buckets[i].UserAgent < out.Buckets[j].UserAgent
					}
					return out.Buckets[i].ClientType < out.Buckets[j].ClientType
				}
				return out.Buckets[i].Model < out.Buckets[j].Model
			}
			return out.Buckets[i].Provider < out.Buckets[j].Provider
		}
		return out.Buckets[i].StartAt.Before(out.Buckets[j].StartAt)
	})
	return out
}

func (s *StatsStore) Flush() {
	if s == nil || s.db == nil {
		return
	}
	_ = s.db.Flush()
}
