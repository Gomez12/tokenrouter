package logstore

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lkarlslund/tokenrouter/pkg/cache"
)

const (
	defaultMaxLines = 5000
	saveInterval    = 2 * time.Second
)

type Settings struct {
	MaxLines int `json:"max_lines"`
}

type Entry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
}

type ListFilter struct {
	Level string
	Query string
	Limit int
}

type persisted struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

type Store struct {
	mu sync.RWMutex

	path     string
	settings Settings
	entries  []Entry

	dirty    bool
	lastSave time.Time
}

type Sink struct {
	store *Store
	mu    sync.Mutex
	buf   []byte
}

func normalizeSettings(s Settings) Settings {
	out := s
	if out.MaxLines <= 0 {
		out.MaxLines = defaultMaxLines
	}
	return out
}

func NewStore(path string, settings Settings) *Store {
	s := &Store{
		path:     strings.TrimSpace(path),
		settings: normalizeSettings(settings),
		entries:  []Entry{},
	}
	if s.path != "" {
		s.load()
	}
	s.pruneLocked()
	return s
}

func (s *Store) Settings() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settings
}

func (s *Store) UpdateSettings(settings Settings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings = normalizeSettings(settings)
	s.pruneLocked()
	s.dirty = true
	s.saveLocked(true)
}

func (s *Store) Add(level, message string, ts time.Time) {
	level = normalizeLevel(level)
	message = strings.TrimSpace(stripANSI(message))
	if message == "" {
		return
	}
	if ts.IsZero() {
		ts = time.Now().UTC()
	} else {
		ts = ts.UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, Entry{
		ID:        fmt.Sprintf("log-%d-%d", ts.UnixNano(), len(s.entries)+1),
		Timestamp: ts,
		Level:     level,
		Message:   message,
	})
	s.pruneLocked()
	s.dirty = true
	s.saveLocked(false)
}

func (s *Store) List(filter ListFilter) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	level := normalizeLevel(filter.Level)
	query := strings.ToLower(strings.TrimSpace(filter.Query))
	limit := filter.Limit
	if limit <= 0 {
		limit = 500
	}
	if limit > 10000 {
		limit = 10000
	}

	out := make([]Entry, 0, min(limit, len(s.entries)))
	for i := len(s.entries) - 1; i >= 0; i-- {
		e := s.entries[i]
		if level != "" && level != "all" && e.Level != level {
			continue
		}
		if query != "" {
			hay := strings.ToLower(e.Message + "\n" + e.Level)
			if !strings.Contains(hay, query) {
				continue
			}
		}
		out = append(out, e)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (s *Store) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveLocked(true)
}

func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = s.entries[:0]
	s.dirty = true
	s.saveLocked(true)
}

func (s *Store) Writer() io.Writer {
	return &Sink{store: s}
}

func (w *Sink) Write(p []byte) (int, error) {
	if w == nil || w.store == nil {
		return len(p), nil
	}
	w.mu.Lock()
	w.buf = append(w.buf, p...)
	for {
		idx := bytes.IndexByte(w.buf, '\n')
		if idx < 0 {
			break
		}
		line := string(bytes.TrimSpace(w.buf[:idx]))
		w.buf = w.buf[idx+1:]
		w.consumeLine(line)
	}
	w.mu.Unlock()
	return len(p), nil
}

func (w *Sink) consumeLine(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	w.store.Add(extractLevel(line), line, time.Now().UTC())
}

func (s *Store) load() {
	var p persisted
	if err := cache.LoadJSON(s.path, &p); err != nil {
		return
	}
	if len(p.Entries) == 0 {
		return
	}
	s.entries = p.Entries
}

func (s *Store) pruneLocked() {
	maxLines := s.settings.MaxLines
	if maxLines <= 0 {
		maxLines = defaultMaxLines
	}
	if len(s.entries) <= maxLines {
		return
	}
	start := len(s.entries) - maxLines
	if start < 0 {
		start = 0
	}
	s.entries = append([]Entry(nil), s.entries[start:]...)
}

func (s *Store) saveLocked(force bool) {
	if strings.TrimSpace(s.path) == "" || !s.dirty {
		return
	}
	now := time.Now().UTC()
	if !force && !s.lastSave.IsZero() && now.Sub(s.lastSave) < saveInterval {
		return
	}
	cp := append([]Entry(nil), s.entries...)
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].Timestamp.Equal(cp[j].Timestamp) {
			return cp[i].ID < cp[j].ID
		}
		return cp[i].Timestamp.Before(cp[j].Timestamp)
	})
	if err := cache.SaveJSON(s.path, persisted{
		Version: 1,
		Entries: cp,
	}); err != nil {
		return
	}
	s.lastSave = now
	s.dirty = false
}

func normalizeLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return "debug"
	case "info":
		return "info"
	case "warn", "warning":
		return "warn"
	case "error":
		return "error"
	case "fatal":
		return "fatal"
	case "all":
		return "all"
	default:
		return ""
	}
}

func extractLevel(line string) string {
	u := strings.ToUpper(stripANSI(line))
	switch {
	case strings.Contains(u, " DEBUG "), strings.HasPrefix(u, "DEBUG "):
		return "debug"
	case strings.Contains(u, " INFO "), strings.HasPrefix(u, "INFO "):
		return "info"
	case strings.Contains(u, " WARN "), strings.Contains(u, " WARNING "), strings.HasPrefix(u, "WARN "):
		return "warn"
	case strings.Contains(u, " ERROR "), strings.HasPrefix(u, "ERROR "):
		return "error"
	case strings.Contains(u, " FATAL "), strings.HasPrefix(u, "FATAL "):
		return "fatal"
	default:
		return "info"
	}
}

func stripANSI(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	inEsc := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if !inEsc {
			if ch == 0x1b {
				inEsc = true
				continue
			}
			b.WriteByte(ch)
			continue
		}
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
			inEsc = false
		}
	}
	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
