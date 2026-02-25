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
		if !logLevelMatchesFilter(level, e.Level) {
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

func logLevelMatchesFilter(filterLevel, entryLevel string) bool {
	f := normalizeLevel(filterLevel)
	if f == "" || f == "all" {
		return true
	}
	ev := normalizeLevel(entryLevel)
	if ev == "" {
		return false
	}
	// Dropdown order is trace -> debug -> info -> warn -> error -> fatal.
	// "selected and below" means selected plus items below in that list.
	return logLevelRank(ev) >= logLevelRank(f)
}

func logLevelRank(level string) int {
	switch normalizeLevel(level) {
	case "trace":
		return 0
	case "debug":
		return 1
	case "info":
		return 2
	case "warn":
		return 3
	case "error":
		return 4
	case "fatal":
		return 5
	default:
		return -1
	}
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
	w.store.Add(extractLevel(line), extractMessage(line), time.Now().UTC())
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
	case "trace", "trac":
		return "trace"
	case "debug", "debu":
		return "debug"
	case "info", "inf":
		return "info"
	case "warn", "warning", "wrn":
		return "warn"
	case "error", "erro", "err":
		return "error"
	case "fatal", "fata":
		return "fatal"
	case "all":
		return "all"
	default:
		return ""
	}
}

func extractLevel(line string) string {
	u := strings.ToUpper(stripANSI(line))
	normalized := strings.ReplaceAll(u, "\t", " ")
	normalized = " " + normalized + " "
	switch {
	case strings.Contains(normalized, " LEVEL=TRACE "), strings.Contains(normalized, " LEVEL=TRAC "),
		strings.Contains(normalized, " TRACE "), strings.Contains(normalized, " TRAC "),
		strings.HasPrefix(strings.TrimSpace(u), "TRACE "), strings.HasPrefix(strings.TrimSpace(u), "TRAC "):
		return "trace"
	case strings.Contains(normalized, " LEVEL=DEBUG "), strings.Contains(normalized, " LEVEL=DEBU "),
		strings.Contains(normalized, " DEBUG "), strings.Contains(normalized, " DEBU "),
		strings.HasPrefix(strings.TrimSpace(u), "DEBUG "), strings.HasPrefix(strings.TrimSpace(u), "DEBU "):
		return "debug"
	case strings.Contains(normalized, " LEVEL=INFO "),
		strings.Contains(normalized, " INFO "),
		strings.HasPrefix(strings.TrimSpace(u), "INFO "):
		return "info"
	case strings.Contains(normalized, " LEVEL=WARN "), strings.Contains(normalized, " LEVEL=WARNING "),
		strings.Contains(normalized, " WARN "), strings.Contains(normalized, " WARNING "),
		strings.HasPrefix(strings.TrimSpace(u), "WARN "):
		return "warn"
	case strings.Contains(normalized, " LEVEL=ERROR "), strings.Contains(normalized, " LEVEL=ERRO "),
		strings.Contains(normalized, " ERROR "), strings.Contains(normalized, " ERRO "),
		strings.HasPrefix(strings.TrimSpace(u), "ERROR "), strings.HasPrefix(strings.TrimSpace(u), "ERRO "):
		return "error"
	case strings.Contains(normalized, " LEVEL=FATAL "), strings.Contains(normalized, " LEVEL=FATA "),
		strings.Contains(normalized, " FATAL "), strings.Contains(normalized, " FATA "),
		strings.HasPrefix(strings.TrimSpace(u), "FATAL "), strings.HasPrefix(strings.TrimSpace(u), "FATA "):
		return "fatal"
	default:
		return "info"
	}
}

func extractMessage(line string) string {
	s := strings.TrimSpace(stripANSI(line))
	if s == "" {
		return ""
	}
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return s
	}

	// Structured log lines often encode time/level as key-value pairs.
	if strings.Contains(strings.ToLower(s), "level=") || strings.Contains(strings.ToLower(s), "time=") {
		out := make([]string, 0, len(fields))
		for _, f := range fields {
			fl := strings.ToLower(strings.TrimSpace(f))
			switch {
			case strings.HasPrefix(fl, "time="),
				strings.HasPrefix(fl, "timestamp="),
				strings.HasPrefix(fl, "ts="),
				strings.HasPrefix(fl, "level="):
				continue
			default:
				out = append(out, f)
			}
		}
		if len(out) > 0 {
			return strings.TrimSpace(strings.Join(out, " "))
		}
	}

	// Plain text format: "<timestamp> <level> message..."
	if len(fields) >= 2 && looksTimestampToken(fields[0]) && looksLevelToken(fields[1]) {
		return strings.TrimSpace(strings.Join(fields[2:], " "))
	}
	// Plain text format with split date/time: "<date> <time> <level> message..."
	if len(fields) >= 3 && looksTimestampToken(fields[0]+" "+fields[1]) && looksLevelToken(fields[2]) {
		return strings.TrimSpace(strings.Join(fields[3:], " "))
	}
	// Plain text format: "<level> message..."
	if len(fields) >= 1 && looksLevelToken(fields[0]) {
		return strings.TrimSpace(strings.Join(fields[1:], " "))
	}
	return s
}

func looksTimestampToken(v string) bool {
	s := strings.TrimSpace(v)
	if s == "" {
		return false
	}
	if strings.Contains(s, "T") && strings.Contains(s, ":") {
		return true
	}
	if strings.Contains(s, "/") && strings.Contains(s, ":") {
		return true
	}
	if strings.Contains(s, "-") && strings.Contains(s, ":") {
		return true
	}
	return false
}

func looksLevelToken(v string) bool {
	s := strings.ToUpper(strings.TrimSpace(v))
	switch s {
	case "TRACE", "TRAC", "DEBUG", "DEBU", "INFO", "WARN", "WARNING", "ERROR", "ERRO", "FATAL", "FATA":
		return true
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "level=")
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
