package conversations

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const saveInterval = 2 * time.Second
const defaultHeuristicGap = 10 * time.Minute

const (
	defaultMaxItems   = 5000
	defaultMaxAgeDays = 30
)

type Settings struct {
	Enabled    bool `json:"enabled"`
	MaxItems   int  `json:"max_items"`
	MaxAgeDays int  `json:"max_age_days"`
}

type ProtocolIDs struct {
	RequestConversationID   string `json:"request_conversation_id,omitempty"`
	RequestPreviousResponse string `json:"request_previous_response_id,omitempty"`
	ResponseID              string `json:"response_id,omitempty"`
}

type Record struct {
	ID                   string            `json:"id"`
	ConversationKey      string            `json:"conversation_key"`
	CreatedAt            time.Time         `json:"created_at"`
	UpdatedAt            time.Time         `json:"updated_at"`
	Endpoint             string            `json:"endpoint"`
	Provider             string            `json:"provider"`
	Model                string            `json:"model"`
	RemoteIP             string            `json:"remote_ip,omitempty"`
	APIKeyName           string            `json:"api_key_name,omitempty"`
	RequestHeaders       map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders      map[string]string `json:"response_headers,omitempty"`
	RequestPayload       json.RawMessage   `json:"request_payload,omitempty"`
	ResponsePayload      json.RawMessage   `json:"response_payload,omitempty"`
	RequestTextMarkdown  string            `json:"request_text_markdown,omitempty"`
	ResponseTextMarkdown string            `json:"response_text_markdown,omitempty"`
	StatusCode           int               `json:"status_code"`
	LatencyMS            int64             `json:"latency_ms"`
	Stream               bool              `json:"stream"`
	ProtocolIDs          ProtocolIDs       `json:"protocol_ids,omitempty"`
}

type ThreadSummary struct {
	ConversationKey string    `json:"conversation_key"`
	LastAt          time.Time `json:"last_at"`
	Count           int       `json:"count"`
	Provider        string    `json:"provider,omitempty"`
	Model           string    `json:"model,omitempty"`
	APIKeyName      string    `json:"api_key_name,omitempty"`
	RemoteIP        string    `json:"remote_ip,omitempty"`
	LastPreview     string    `json:"last_preview,omitempty"`
}

type ListFilter struct {
	Query      string
	Provider   string
	Model      string
	APIKeyName string
	RemoteIP   string
	Limit      int
	Before     time.Time
}

type CaptureInput struct {
	Timestamp            time.Time
	Endpoint             string
	Provider             string
	Model                string
	RemoteIP             string
	APIKeyName           string
	RequestHeaders       map[string]string
	ResponseHeaders      map[string]string
	RequestPayload       []byte
	ResponsePayload      []byte
	RequestTextMarkdown  string
	ResponseTextMarkdown string
	StatusCode           int
	LatencyMS            int64
	Stream               bool
	ProtocolIDs          ProtocolIDs
}

type heuristicState struct {
	ConversationKey string
	LastAt          time.Time
}

type persisted struct {
	Version  int      `json:"version"`
	Settings Settings `json:"settings"`
	Records  []Record `json:"records"`
}

type Store struct {
	mu sync.RWMutex

	path      string
	settings  Settings
	records   []Record
	response  map[string]string
	heuristic map[string]heuristicState

	dirty    bool
	lastSave time.Time
}

func DefaultSettings() Settings {
	return Settings{Enabled: true, MaxItems: defaultMaxItems, MaxAgeDays: defaultMaxAgeDays}
}

func normalizeSettings(in Settings) Settings {
	out := in
	if out.MaxItems <= 0 {
		out.MaxItems = defaultMaxItems
	}
	if out.MaxAgeDays <= 0 {
		out.MaxAgeDays = defaultMaxAgeDays
	}
	return out
}

func NewStore(path string, settings Settings) *Store {
	s := &Store{
		path:      strings.TrimSpace(path),
		settings:  normalizeSettings(settings),
		response:  map[string]string{},
		heuristic: map[string]heuristicState{},
		records:   []Record{},
	}
	if s.path != "" {
		s.load()
	}
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
	s.pruneLocked(time.Now().UTC())
	s.dirty = true
	s.saveLocked(true)
}

func (s *Store) Add(in CaptureInput) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.settings.Enabled {
		return Record{}, false
	}
	now := in.Timestamp.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	convKey := s.resolveConversationKeyLocked(in, now)
	rec := Record{
		ID:                   fmt.Sprintf("conv-%d-%d", now.UnixNano(), len(s.records)+1),
		ConversationKey:      convKey,
		CreatedAt:            now,
		UpdatedAt:            now,
		Endpoint:             strings.TrimSpace(in.Endpoint),
		Provider:             strings.TrimSpace(in.Provider),
		Model:                strings.TrimSpace(in.Model),
		RemoteIP:             strings.TrimSpace(in.RemoteIP),
		APIKeyName:           strings.TrimSpace(in.APIKeyName),
		RequestHeaders:       cloneMap(in.RequestHeaders),
		ResponseHeaders:      cloneMap(in.ResponseHeaders),
		RequestPayload:       cloneBytes(in.RequestPayload),
		ResponsePayload:      cloneBytes(in.ResponsePayload),
		RequestTextMarkdown:  strings.TrimSpace(in.RequestTextMarkdown),
		ResponseTextMarkdown: strings.TrimSpace(in.ResponseTextMarkdown),
		StatusCode:           in.StatusCode,
		LatencyMS:            in.LatencyMS,
		Stream:               in.Stream,
		ProtocolIDs:          in.ProtocolIDs,
	}
	s.records = append(s.records, rec)

	if rid := strings.TrimSpace(in.ProtocolIDs.ResponseID); rid != "" {
		s.response[rid] = convKey
	}
	hk := s.heuristicKey(rec.Endpoint, rec.APIKeyName, rec.RemoteIP, rec.Model)
	s.heuristic[hk] = heuristicState{ConversationKey: convKey, LastAt: now}

	s.pruneLocked(now)
	s.dirty = true
	s.saveLocked(false)
	return rec, true
}

func (s *Store) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveLocked(true)
}

func (s *Store) ListThreads(filter ListFilter) ([]ThreadSummary, string, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 5000 {
		limit = 5000
	}

	byKey := map[string]*ThreadSummary{}
	q := strings.ToLower(strings.TrimSpace(filter.Query))
	provider := strings.ToLower(strings.TrimSpace(filter.Provider))
	model := strings.ToLower(strings.TrimSpace(filter.Model))
	keyName := strings.ToLower(strings.TrimSpace(filter.APIKeyName))
	remote := strings.ToLower(strings.TrimSpace(filter.RemoteIP))

	for i := range s.records {
		r := s.records[i]
		if provider != "" && !strings.Contains(strings.ToLower(r.Provider), provider) {
			continue
		}
		if model != "" && !strings.Contains(strings.ToLower(r.Model), model) {
			continue
		}
		if keyName != "" && !strings.Contains(strings.ToLower(r.APIKeyName), keyName) {
			continue
		}
		if remote != "" && !strings.Contains(strings.ToLower(r.RemoteIP), remote) {
			continue
		}
		if q != "" {
			hay := strings.ToLower(strings.Join([]string{
				r.Provider,
				r.Model,
				r.APIKeyName,
				r.RemoteIP,
				r.RequestTextMarkdown,
				r.ResponseTextMarkdown,
				string(r.RequestPayload),
				string(r.ResponsePayload),
			}, "\n"))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		ts := r.UpdatedAt
		if ts.IsZero() {
			ts = r.CreatedAt
		}
		if !filter.Before.IsZero() && !ts.Before(filter.Before) {
			continue
		}

		t := byKey[r.ConversationKey]
		if t == nil {
			t = &ThreadSummary{ConversationKey: r.ConversationKey}
			byKey[r.ConversationKey] = t
		}
		t.Count++
		if ts.After(t.LastAt) {
			t.LastAt = ts
			t.Provider = r.Provider
			t.Model = r.Model
			t.APIKeyName = r.APIKeyName
			t.RemoteIP = r.RemoteIP
			if preview := strings.TrimSpace(r.ResponseTextMarkdown); preview != "" {
				if len(preview) > 160 {
					preview = preview[:160] + "..."
				}
				t.LastPreview = preview
			} else if preview := strings.TrimSpace(r.RequestTextMarkdown); preview != "" {
				if len(preview) > 160 {
					preview = preview[:160] + "..."
				}
				t.LastPreview = preview
			}
		}
	}

	out := make([]ThreadSummary, 0, len(byKey))
	for _, t := range byKey {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastAt.Equal(out[j].LastAt) {
			return out[i].ConversationKey < out[j].ConversationKey
		}
		return out[i].LastAt.After(out[j].LastAt)
	})

	total := len(out)
	nextBefore := ""
	if len(out) > limit {
		nextBefore = out[limit-1].LastAt.Format(time.RFC3339Nano)
		out = out[:limit]
	}
	return out, nextBefore, total
}

func (s *Store) Conversation(key string) []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key = strings.TrimSpace(key)
	out := make([]Record, 0, 32)
	for _, r := range s.records {
		if r.ConversationKey != key {
			continue
		}
		out = append(out, cloneRecord(r))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func (s *Store) DeleteConversation(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	key = strings.TrimSpace(key)
	if key == "" || len(s.records) == 0 {
		return 0
	}
	kept := s.records[:0]
	removed := 0
	for _, r := range s.records {
		if strings.TrimSpace(r.ConversationKey) == key {
			removed++
			continue
		}
		kept = append(kept, r)
	}
	if removed == 0 {
		return 0
	}
	s.records = kept
	s.rebuildIndexesLocked()
	s.dirty = true
	s.saveLocked(true)
	return removed
}

func (s *Store) resolveConversationKeyLocked(in CaptureInput, now time.Time) string {
	if id := strings.TrimSpace(in.ProtocolIDs.RequestConversationID); id != "" {
		return "cid:" + id
	}
	if prev := strings.TrimSpace(in.ProtocolIDs.RequestPreviousResponse); prev != "" {
		if key := strings.TrimSpace(s.response[prev]); key != "" {
			return key
		}
		return "prev:" + prev
	}

	hk := s.heuristicKey(in.Endpoint, in.APIKeyName, in.RemoteIP, in.Model)
	if hs, ok := s.heuristic[hk]; ok {
		if now.Sub(hs.LastAt) <= defaultHeuristicGap {
			return hs.ConversationKey
		}
	}
	return fmt.Sprintf("heur:%d", now.UnixNano())
}

func (s *Store) heuristicKey(endpoint, apiKeyName, remoteIP, model string) string {
	return strings.ToLower(strings.TrimSpace(endpoint)) + "|" +
		strings.ToLower(strings.TrimSpace(apiKeyName)) + "|" +
		strings.ToLower(strings.TrimSpace(remoteIP)) + "|" +
		strings.ToLower(strings.TrimSpace(model))
}

func (s *Store) pruneLocked(now time.Time) {
	if len(s.records) == 0 {
		return
	}
	maxAge := time.Duration(s.settings.MaxAgeDays) * 24 * time.Hour
	cutoff := now.Add(-maxAge)
	kept := s.records[:0]
	for _, r := range s.records {
		if !r.CreatedAt.IsZero() && r.CreatedAt.Before(cutoff) {
			continue
		}
		kept = append(kept, r)
	}
	s.records = kept
	if len(s.records) > s.settings.MaxItems {
		s.records = s.records[len(s.records)-s.settings.MaxItems:]
	}
	s.rebuildIndexesLocked()
}

func (s *Store) rebuildIndexesLocked() {
	s.response = map[string]string{}
	s.heuristic = map[string]heuristicState{}
	for _, r := range s.records {
		if rid := strings.TrimSpace(r.ProtocolIDs.ResponseID); rid != "" {
			s.response[rid] = r.ConversationKey
		}
		hk := s.heuristicKey(r.Endpoint, r.APIKeyName, r.RemoteIP, r.Model)
		st, ok := s.heuristic[hk]
		if !ok || r.CreatedAt.After(st.LastAt) {
			s.heuristic[hk] = heuristicState{ConversationKey: r.ConversationKey, LastAt: r.CreatedAt}
		}
	}
}

func (s *Store) load() {
	b, err := os.ReadFile(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		return
	}
	if p.Version != 1 {
		return
	}
	s.records = append([]Record(nil), p.Records...)
	if p.Settings.MaxItems > 0 || p.Settings.MaxAgeDays > 0 {
		s.settings = normalizeSettings(p.Settings)
	}
	s.pruneLocked(time.Now().UTC())
	s.dirty = false
}

func (s *Store) saveLocked(force bool) {
	if strings.TrimSpace(s.path) == "" || !s.dirty {
		return
	}
	if !force && time.Since(s.lastSave) < saveInterval {
		return
	}
	p := persisted{Version: 1, Settings: s.settings, Records: s.records}
	b, err := json.MarshalIndent(p, "", "  ")
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

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func cloneRecord(in Record) Record {
	in.RequestHeaders = cloneMap(in.RequestHeaders)
	in.ResponseHeaders = cloneMap(in.ResponseHeaders)
	in.RequestPayload = cloneBytes(in.RequestPayload)
	in.ResponsePayload = cloneBytes(in.ResponsePayload)
	return in
}
