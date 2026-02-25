package usagedb

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStoreAppendAndSummary(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "usage-db")
	s := New(dir)
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)

	if err := s.Append(Event{
		Timestamp:      now.Add(-2 * time.Minute),
		Provider:       "openai",
		Model:          "openai/gpt-5",
		StatusCode:     200,
		PromptTokens:   10,
		CompletionToks: 5,
		TotalTokens:    15,
		LatencyMS:      120,
		PromptTPS:      100,
		GenTPS:         50,
	}); err != nil {
		t.Fatalf("append event: %v", err)
	}
	if err := s.Append(Event{
		Timestamp:      now.Add(-1 * time.Minute),
		Provider:       "openai",
		Model:          "openai/gpt-5",
		StatusCode:     500,
		PromptTokens:   0,
		CompletionToks: 0,
		TotalTokens:    0,
		LatencyMS:      80,
		PromptTPS:      0,
		GenTPS:         0,
	}); err != nil {
		t.Fatalf("append event: %v", err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	sum, err := s.Summary(1*time.Hour, now)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if sum.Requests != 2 {
		t.Fatalf("expected 2 requests, got %d", sum.Requests)
	}
	if sum.TotalTokens != 15 {
		t.Fatalf("expected 15 tokens, got %d", sum.TotalTokens)
	}
	if got := sum.RequestsPerProvider["openai"]; got != 2 {
		t.Fatalf("expected provider requests 2, got %d", got)
	}
	if len(sum.Buckets) == 0 {
		t.Fatal("expected summary buckets")
	}
	for _, b := range sum.Buckets {
		if b.SlotSeconds != 60 {
			t.Fatalf("expected 60-second buckets for 1h summary, got %d", b.SlotSeconds)
		}
	}
}

func TestStoreCompactsRawToRollup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "usage-db")
	s := New(dir)
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)

	s.settings.RawRetention = time.Hour
	s.settings.Rollup5Retention = 3 * time.Hour
	s.settings.Rollup1hRetention = 24 * time.Hour

	events := []Event{
		{
			Timestamp:      now.Add(-2 * time.Hour),
			Provider:       "groq",
			Model:          "groq/llama",
			StatusCode:     200,
			PromptTokens:   6,
			CompletionToks: 4,
			TotalTokens:    10,
			LatencyMS:      100,
			PromptTPS:      60,
			GenTPS:         40,
		},
		{
			Timestamp:      now.Add(-2*time.Hour + 2*time.Minute),
			Provider:       "groq",
			Model:          "groq/llama",
			StatusCode:     200,
			PromptTokens:   3,
			CompletionToks: 2,
			TotalTokens:    5,
			LatencyMS:      70,
			PromptTPS:      60,
			GenTPS:         40,
		},
	}
	for _, evt := range events {
		if err := s.Append(evt); err != nil {
			t.Fatalf("append event: %v", err)
		}
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := s.Compact(now); err != nil {
		t.Fatalf("compact: %v", err)
	}

	sum, err := s.Summary(4*time.Hour, now)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if sum.Requests != 2 {
		t.Fatalf("expected 2 requests, got %d", sum.Requests)
	}
	if sum.TotalTokens != 15 {
		t.Fatalf("expected 15 tokens, got %d", sum.TotalTokens)
	}
}

func TestStoreCompacts5mTo1hAndPrunes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "usage-db")
	s := New(dir)
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)

	s.settings.RawRetention = time.Hour
	s.settings.Rollup5Retention = 2 * time.Hour
	s.settings.Rollup1hRetention = 5 * time.Hour

	if err := s.Append(Event{
		Timestamp:      now.Add(-3 * time.Hour),
		Provider:       "openai",
		Model:          "openai/gpt-5",
		StatusCode:     200,
		PromptTokens:   12,
		CompletionToks: 8,
		TotalTokens:    20,
		LatencyMS:      150,
		PromptTPS:      80,
		GenTPS:         40,
	}); err != nil {
		t.Fatalf("append event: %v", err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := s.Compact(now); err != nil {
		t.Fatalf("compact: %v", err)
	}

	sum, err := s.Summary(6*time.Hour, now)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if sum.Requests != 1 {
		t.Fatalf("expected 1 request, got %d", sum.Requests)
	}
	if sum.TotalTokens != 20 {
		t.Fatalf("expected 20 total tokens, got %d", sum.TotalTokens)
	}

	if err := s.Compact(now.Add(10 * time.Hour)); err != nil {
		t.Fatalf("compact prune: %v", err)
	}
	sumAfter, err := s.Summary(24*time.Hour, now.Add(10*time.Hour))
	if err != nil {
		t.Fatalf("summary after prune: %v", err)
	}
	if sumAfter.Requests != 0 {
		t.Fatalf("expected pruned requests, got %d", sumAfter.Requests)
	}
}
