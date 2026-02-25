package logstore

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStorePersistsAndRetainsMaxLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs.json")
	s := NewStore(path, Settings{MaxLines: 3})
	s.Add("info", "one", time.Unix(1, 0))
	s.Add("warn", "two", time.Unix(2, 0))
	s.Add("error", "three", time.Unix(3, 0))
	s.Add("debug", "four", time.Unix(4, 0))
	s.Flush()

	out := NewStore(path, Settings{MaxLines: 3})
	entries := out.List(ListFilter{Level: "all", Limit: 10})
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].Message != "four" || entries[1].Message != "three" || entries[2].Message != "two" {
		t.Fatalf("unexpected order/messages: %+v", entries)
	}
}

func TestSinkParsesLevelsAndFilters(t *testing.T) {
	s := NewStore("", Settings{MaxLines: 100})
	w := s.Writer()
	_, _ = w.Write([]byte("2026-01-01T00:00:00Z TRAC ultra\n"))
	_, _ = w.Write([]byte("2026-01-01T00:00:00Z DEBU hello\n"))
	_, _ = w.Write([]byte("2026-01-01T00:00:01Z INFO world\n"))
	_, _ = w.Write([]byte("2026-01-01T00:00:02Z ERRO fail\n"))

	traceEntries := s.List(ListFilter{Level: "trace", Limit: 10})
	if len(traceEntries) != 4 {
		t.Fatalf("expected 4 entries for trace-and-below filter, got %d", len(traceEntries))
	}
	if traceEntries[3].Level != "trace" {
		t.Fatalf("expected oldest entry to be trace, got %+v", traceEntries[3])
	}

	debugEntries := s.List(ListFilter{Level: "debug", Limit: 10})
	if len(debugEntries) != 3 {
		t.Fatalf("expected 3 entries for debug-and-below filter, got %d", len(debugEntries))
	}
	if debugEntries[0].Message == "" {
		t.Fatal("expected debug message")
	}
	infoEntries := s.List(ListFilter{Level: "info", Limit: 10})
	if len(infoEntries) != 2 {
		t.Fatalf("expected 2 entries for info-and-below filter, got %d", len(infoEntries))
	}
	seenInfo := false
	seenError := false
	for _, e := range infoEntries {
		if e.Level == "info" {
			seenInfo = true
		}
		if e.Level == "error" {
			seenError = true
		}
	}
	if !seenInfo || !seenError {
		t.Fatalf("expected info and error levels, got %+v", infoEntries)
	}
	query := s.List(ListFilter{Level: "all", Query: "world", Limit: 10})
	if len(query) != 1 {
		t.Fatalf("expected 1 query match, got %d", len(query))
	}
}

func TestClearRemovesEntries(t *testing.T) {
	s := NewStore("", Settings{MaxLines: 100})
	s.Add("info", "hello", time.Now().UTC())
	if got := len(s.List(ListFilter{Level: "all", Limit: 10})); got != 1 {
		t.Fatalf("expected 1 entry before clear, got %d", got)
	}
	s.Clear()
	if got := len(s.List(ListFilter{Level: "all", Limit: 10})); got != 0 {
		t.Fatalf("expected 0 entries after clear, got %d", got)
	}
}
