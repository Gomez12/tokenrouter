package proxy

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStatsStoreAggregatesInto5MinuteBuckets(t *testing.T) {
	s := NewStatsStore(100)
	base := time.Date(2026, 2, 23, 20, 0, 10, 0, time.UTC)
	s.Add(UsageEvent{
		Timestamp:      base,
		Provider:       "openai",
		Model:          "openai/gpt-5",
		PromptTokens:   100,
		CompletionToks: 40,
		TotalTokens:    140,
		LatencyMS:      500,
		PromptTPS:      200,
		GenTPS:         80,
	})
	s.Add(UsageEvent{
		Timestamp:      base.Add(2 * time.Minute),
		Provider:       "openai",
		Model:          "openai/gpt-5",
		PromptTokens:   50,
		CompletionToks: 20,
		TotalTokens:    70,
		LatencyMS:      250,
		PromptTPS:      200,
		GenTPS:         80,
	})

	summary := s.Summary(2 * time.Hour)
	if summary.Requests != 2 {
		t.Fatalf("expected 2 requests, got %d", summary.Requests)
	}
	if summary.PromptTokens != 150 || summary.CompletionTokens != 60 || summary.TotalTokens != 210 {
		t.Fatalf("unexpected token totals: prompt=%d completion=%d total=%d", summary.PromptTokens, summary.CompletionTokens, summary.TotalTokens)
	}
	if got := summary.RequestsPerProvider["openai"]; got != 2 {
		t.Fatalf("expected provider count 2, got %d", got)
	}
	if got := summary.RequestsPerModel["openai/gpt-5"]; got != 2 {
		t.Fatalf("expected model count 2, got %d", got)
	}
}

func TestPersistentStatsStoreLoadsFromDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage-stats.json")
	s := NewPersistentStatsStore(100, path)
	ts := time.Now().Add(-3 * time.Minute)
	s.Add(UsageEvent{
		Timestamp:      ts,
		Provider:       "groq",
		Model:          "groq/llama-4",
		PromptTokens:   10,
		CompletionToks: 5,
		TotalTokens:    15,
		LatencyMS:      100,
		PromptTPS:      100,
		GenTPS:         50,
	})
	s.mu.Lock()
	s.saveLocked()
	s.mu.Unlock()

	loaded := NewPersistentStatsStore(100, path)
	summary := loaded.Summary(time.Hour)
	if summary.Requests != 1 {
		t.Fatalf("expected 1 request after load, got %d", summary.Requests)
	}
	if summary.TotalTokens != 15 {
		t.Fatalf("expected 15 total tokens after load, got %d", summary.TotalTokens)
	}
}

func TestStatsStoreAggregatesClientMetadata(t *testing.T) {
	s := NewStatsStore(100)
	now := time.Now().UTC()
	s.Add(UsageEvent{
		Timestamp:      now,
		Provider:       "openai",
		Model:          "openai/gpt-5",
		ClientType:     "openai-python",
		ClientIP:       "127.0.0.1",
		APIKeyName:     "Dev Laptop",
		PromptTokens:   10,
		CompletionToks: 5,
		TotalTokens:    15,
		LatencyMS:      100,
		PromptTPS:      100,
		GenTPS:         50,
	})
	s.Add(UsageEvent{
		Timestamp:      now.Add(10 * time.Second),
		Provider:       "openai",
		Model:          "openai/gpt-5",
		ClientType:     "curl",
		ClientIP:       "10.0.0.7",
		APIKeyName:     "CI Runner",
		PromptTokens:   10,
		CompletionToks: 5,
		TotalTokens:    15,
		LatencyMS:      100,
		PromptTPS:      100,
		GenTPS:         50,
	})

	summary := s.Summary(time.Hour)
	if got := summary.RequestsPerClientType["openai-python"]; got != 1 {
		t.Fatalf("expected openai-python count 1, got %d", got)
	}
	if got := summary.RequestsPerClientType["curl"]; got != 1 {
		t.Fatalf("expected curl count 1, got %d", got)
	}
	if got := summary.RequestsPerClientIP["127.0.0.1"]; got != 1 {
		t.Fatalf("expected client ip 127.0.0.1 count 1, got %d", got)
	}
	if got := summary.RequestsPerClientIP["10.0.0.7"]; got != 1 {
		t.Fatalf("expected client ip 10.0.0.7 count 1, got %d", got)
	}
	if got := summary.RequestsPerAPIKeyName["Dev Laptop"]; got != 1 {
		t.Fatalf("expected api key name Dev Laptop count 1, got %d", got)
	}
	if got := summary.RequestsPerAPIKeyName["CI Runner"]; got != 1 {
		t.Fatalf("expected api key name CI Runner count 1, got %d", got)
	}
}
