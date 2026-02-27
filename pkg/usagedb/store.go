package usagedb

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
)

const (
	defaultRawRetention      = 7 * 24 * time.Hour
	defaultRollup5Retention  = 30 * 24 * time.Hour
	defaultRollup1hRetention = 365 * 24 * time.Hour
	defaultSegmentMaxBytes   = int64(0)
	defaultSegmentMaxAge     = 6 * time.Hour
	usageBucketSize          = 5 * time.Minute
	maxSummaryTPS            = 2000.0
)

type Settings struct {
	RawRetention      time.Duration
	Rollup5Retention  time.Duration
	Rollup1hRetention time.Duration
	SegmentMaxBytes   int64
	SegmentMaxAge     time.Duration
}

type Event struct {
	Timestamp      time.Time `json:"timestamp"`
	Provider       string    `json:"provider"`
	Model          string    `json:"model"`
	ClientType     string    `json:"client_type,omitempty"`
	UserAgent      string    `json:"user_agent,omitempty"`
	ClientIP       string    `json:"client_ip,omitempty"`
	APIKeyName     string    `json:"api_key_name,omitempty"`
	StatusCode     int       `json:"status_code"`
	PromptTokens   int       `json:"prompt_tokens"`
	PromptCached   int       `json:"prompt_cached_tokens,omitempty"`
	CompletionToks int       `json:"completion_tokens"`
	TotalTokens    int       `json:"total_tokens"`
	LatencyMS      int64     `json:"latency_ms"`
	PromptTPS      float64   `json:"prompt_tps"`
	GenTPS         float64   `json:"gen_tps"`
}

type Bucket struct {
	StartAt          time.Time `json:"start_at"`
	SlotSeconds      int       `json:"slot_seconds"`
	Provider         string    `json:"provider"`
	Model            string    `json:"model"`
	ClientType       string    `json:"client_type,omitempty"`
	UserAgent        string    `json:"user_agent,omitempty"`
	ClientIP         string    `json:"client_ip,omitempty"`
	APIKeyName       string    `json:"api_key_name,omitempty"`
	Requests         int       `json:"requests"`
	FailedRequests   int       `json:"failed_requests,omitempty"`
	PromptTokens     int       `json:"prompt_tokens"`
	PromptCached     int       `json:"prompt_cached_tokens,omitempty"`
	CompletionTokens int       `json:"completion_tokens"`
	TotalTokens      int       `json:"total_tokens"`
	LatencyMSSum     int64     `json:"latency_ms_sum"`
	PromptTPSSum     float64   `json:"prompt_tps_sum"`
	GenerationTPSSum float64   `json:"generation_tps_sum"`
}

type Summary struct {
	PeriodSeconds         int64
	Requests              int
	FailedRequests        int
	PromptTokens          int
	PromptCachedTokens    int
	CompletionTokens      int
	TotalTokens           int
	AvgLatencyMS          float64
	AvgPromptTPS          float64
	AvgGenerationTPS      float64
	RequestsPerProvider   map[string]int
	RequestsPerModel      map[string]int
	RequestsPerClientType map[string]int
	RequestsPerUserAgent  map[string]int
	RequestsPerClientIP   map[string]int
	RequestsPerAPIKeyName map[string]int
	Buckets               []Bucket
}

type Store struct {
	mu           sync.Mutex
	dir          string
	legacyPath   string
	settings     Settings
	rawWriter    *segmentWriter
	rawWriterDir string
	lastCompact  time.Time
}

type segmentWriter struct {
	pathTmp  string
	dir      string
	seq      int64
	file     *os.File
	enc      *zstd.Encoder
	minTs    time.Time
	maxTs    time.Time
	count    int
	bytesIn  int64
	openedAt time.Time
}

type segmentMeta struct {
	path string
	min  time.Time
	max  time.Time
}

type importState struct {
	Version    int    `json:"version"`
	ImportedAt string `json:"imported_at"`
}

type legacyStatsFile struct {
	Version int            `json:"version"`
	Buckets []legacyBucket `json:"buckets"`
}

type legacyBucket struct {
	StartAt          time.Time `json:"start_at"`
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

func New(path string) *Store {
	dir, legacy := derivePaths(strings.TrimSpace(path))
	s := &Store{dir: dir, legacyPath: legacy, settings: normalizeSettings(Settings{})}
	_ = os.MkdirAll(s.dir, 0o700)
	s.importLegacyIfNeeded()
	return s
}

func normalizeSettings(in Settings) Settings {
	out := in
	if out.RawRetention <= 0 {
		out.RawRetention = defaultRawRetention
	}
	if out.Rollup5Retention <= 0 {
		out.Rollup5Retention = defaultRollup5Retention
	}
	if out.Rollup1hRetention <= 0 {
		out.Rollup1hRetention = defaultRollup1hRetention
	}
	if out.SegmentMaxBytes <= 0 {
		out.SegmentMaxBytes = defaultSegmentMaxBytes
	}
	if out.SegmentMaxAge <= 0 {
		out.SegmentMaxAge = defaultSegmentMaxAge
	}
	return out
}

func derivePaths(path string) (dir string, legacy string) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "usage-db", ""
		}
		return filepath.Join(home, ".cache", "tokenrouter", "usage-db"), ""
	}
	if strings.HasSuffix(path, ".json") {
		base := strings.TrimSuffix(path, ".json")
		return base + "-db", path
	}
	return path, ""
}

func (s *Store) Append(evt Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now().UTC()
	} else {
		evt.Timestamp = evt.Timestamp.UTC()
	}
	evt.ClientType = strings.TrimSpace(evt.ClientType)
	evt.UserAgent = strings.TrimSpace(evt.UserAgent)
	evt.ClientIP = strings.TrimSpace(evt.ClientIP)
	evt.APIKeyName = strings.TrimSpace(evt.APIKeyName)

	if err := s.openRawWriterLocked(evt.Timestamp); err != nil {
		return err
	}
	line, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	if err := s.rawWriter.writeLine(line, evt.Timestamp); err != nil {
		return err
	}
	if s.rawWriter.shouldRotate(s.settings.SegmentMaxBytes, s.settings.SegmentMaxAge) {
		if err := s.closeRawWriterLocked(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Summary(period time.Duration, now time.Time) (Summary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if err := s.compactLocked(now); err != nil {
		return Summary{}, err
	}

	cutoff := now.Add(-period)
	summary := Summary{
		PeriodSeconds:         int64(period.Seconds()),
		RequestsPerProvider:   map[string]int{},
		RequestsPerModel:      map[string]int{},
		RequestsPerClientType: map[string]int{},
		RequestsPerUserAgent:  map[string]int{},
		RequestsPerClientIP:   map[string]int{},
		RequestsPerAPIKeyName: map[string]int{},
	}
	chartSlot := usageBucketSize
	if period <= time.Hour {
		chartSlot = time.Minute
	}

	bucketMap := map[string]*Bucket{}

	readRange := func(root string, from, to time.Time, onEvent func(Event), onBucket func(Bucket)) error {
		if !from.Before(to) {
			return nil
		}
		segs, err := listSegments(root)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		for _, seg := range segs {
			if !overlaps(seg.min, seg.max, from, to) {
				continue
			}
			if onEvent != nil {
				if err := scanEvents(seg.path, from, to, onEvent); err != nil {
					return err
				}
			} else if onBucket != nil {
				if err := scanBuckets(seg.path, from, to, onBucket); err != nil {
					return err
				}
			}
		}
		return nil
	}

	addBucket := func(b Bucket) {
		if b.Requests <= 0 {
			return
		}
		if b.StartAt.Add(time.Duration(max(1, b.SlotSeconds)) * time.Second).Before(cutoff) {
			return
		}
		summary.Requests += b.Requests
		summary.FailedRequests += b.FailedRequests
		summary.PromptTokens += b.PromptTokens
		summary.PromptCachedTokens += b.PromptCached
		summary.CompletionTokens += b.CompletionTokens
		summary.TotalTokens += b.TotalTokens
		summary.AvgLatencyMS += float64(b.LatencyMSSum)

		ptps := b.PromptTPSSum
		gtps := b.GenerationTPSSum
		avgPrompt := ptps / float64(b.Requests)
		avgGen := gtps / float64(b.Requests)
		if avgPrompt > maxSummaryTPS {
			ptps = maxSummaryTPS * float64(b.Requests)
		}
		if avgGen > maxSummaryTPS {
			gtps = maxSummaryTPS * float64(b.Requests)
		}
		summary.AvgPromptTPS += ptps
		summary.AvgGenerationTPS += gtps

		summary.RequestsPerProvider[b.Provider] += b.Requests
		summary.RequestsPerModel[b.Model] += b.Requests
		if b.ClientType != "" {
			summary.RequestsPerClientType[b.ClientType] += b.Requests
		}
		if b.UserAgent != "" {
			summary.RequestsPerUserAgent[b.UserAgent] += b.Requests
		}
		if b.ClientIP != "" {
			summary.RequestsPerClientIP[b.ClientIP] += b.Requests
		}
		if b.APIKeyName != "" {
			summary.RequestsPerAPIKeyName[b.APIKeyName] += b.Requests
		}

		start := b.StartAt.UTC().Truncate(chartSlot)
		k := bucketKey(start, b.Provider, b.Model, b.ClientType, b.UserAgent, b.ClientIP, b.APIKeyName)
		existing := bucketMap[k]
		if existing == nil {
			c := b
			c.StartAt = start
			c.SlotSeconds = int(chartSlot.Seconds())
			existing = &c
			bucketMap[k] = existing
			return
		}
		existing.Requests += b.Requests
		existing.FailedRequests += b.FailedRequests
		existing.PromptTokens += b.PromptTokens
		existing.PromptCached += b.PromptCached
		existing.CompletionTokens += b.CompletionTokens
		existing.TotalTokens += b.TotalTokens
		existing.LatencyMSSum += b.LatencyMSSum
		existing.PromptTPSSum += b.PromptTPSSum
		existing.GenerationTPSSum += b.GenerationTPSSum
	}

	rawFrom := maxTime(cutoff, now.Add(-s.settings.RawRetention))
	roll5From := maxTime(cutoff, now.Add(-s.settings.Rollup5Retention))
	roll5To := now
	roll1From := cutoff
	roll1To := minTime(now.Add(-s.settings.Rollup5Retention), now)

	if chartSlot <= time.Minute {
		if err := readRange(filepath.Join(s.dir, "raw"), rawFrom, now, func(e Event) {
			addBucket(eventToBucket(e, chartSlot))
		}, nil); err != nil {
			return Summary{}, err
		}
	} else {
		if err := readRange(filepath.Join(s.dir, "rollup", "3600"), roll1From, roll1To, nil, addBucket); err != nil {
			return Summary{}, err
		}
		if err := readRange(filepath.Join(s.dir, "rollup", "300"), roll5From, roll5To, nil, addBucket); err != nil {
			return Summary{}, err
		}
		if err := readRange(filepath.Join(s.dir, "raw"), rawFrom, now, func(e Event) {
			addBucket(eventToBucket(e, usageBucketSize))
		}, nil); err != nil {
			return Summary{}, err
		}
	}

	summary.Buckets = make([]Bucket, 0, len(bucketMap))
	for _, b := range bucketMap {
		summary.Buckets = append(summary.Buckets, *b)
	}
	sort.Slice(summary.Buckets, func(i, j int) bool {
		a := summary.Buckets[i]
		b := summary.Buckets[j]
		if a.StartAt.Equal(b.StartAt) {
			if a.Provider == b.Provider {
				if a.Model == b.Model {
					if a.ClientType == b.ClientType {
						if a.UserAgent == b.UserAgent {
							if a.ClientIP == b.ClientIP {
								return a.APIKeyName < b.APIKeyName
							}
							return a.ClientIP < b.ClientIP
						}
						return a.UserAgent < b.UserAgent
					}
					return a.ClientType < b.ClientType
				}
				return a.Model < b.Model
			}
			return a.Provider < b.Provider
		}
		return a.StartAt.Before(b.StartAt)
	})

	if summary.Requests > 0 {
		summary.AvgLatencyMS = summary.AvgLatencyMS / float64(summary.Requests)
		summary.AvgPromptTPS = summary.AvgPromptTPS / float64(summary.Requests)
		summary.AvgGenerationTPS = summary.AvgGenerationTPS / float64(summary.Requests)
	}

	return summary, nil
}

func (s *Store) Compact(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	return s.compactLocked(now)
}

func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeRawWriterLocked()
}

func (s *Store) compactLocked(now time.Time) error {
	if !s.lastCompact.IsZero() && now.Sub(s.lastCompact) < 30*time.Second {
		return nil
	}
	if err := s.closeRawWriterLocked(); err != nil {
		return err
	}
	if err := s.compactRawTo5mLocked(now); err != nil {
		return err
	}
	if err := s.compact5mTo1hLocked(now); err != nil {
		return err
	}
	if err := s.prune1hLocked(now); err != nil {
		return err
	}
	s.lastCompact = now
	return nil
}

func (s *Store) compactRawTo5mLocked(now time.Time) error {
	cutoff := now.Add(-s.settings.RawRetention)
	segs, err := listSegments(filepath.Join(s.dir, "raw"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	candidates := make([]segmentMeta, 0, len(segs))
	for _, seg := range segs {
		if seg.max.Before(cutoff) {
			candidates = append(candidates, seg)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	slog.Info("usage db compacting raw to 5m", "segments", len(candidates), "cutoff", cutoff.Format(time.RFC3339))
	agg := map[string]*Bucket{}
	for _, seg := range candidates {
		err := scanEvents(seg.path, time.Time{}, cutoff, func(evt Event) {
			b := eventToBucket(evt, 5*time.Minute)
			mergeBucket(agg, b)
		})
		if err != nil {
			return err
		}
	}
	if err := s.writeRollupBucketsLocked(300, mapToSortedBuckets(agg)); err != nil {
		return err
	}
	for _, seg := range candidates {
		_ = os.Remove(seg.path)
	}
	slog.Info("usage db compacted raw to 5m", "segments", len(candidates), "buckets", len(agg))
	return nil
}

func (s *Store) compact5mTo1hLocked(now time.Time) error {
	cutoff := now.Add(-s.settings.Rollup5Retention)
	segs, err := listSegments(filepath.Join(s.dir, "rollup", "300"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	candidates := make([]segmentMeta, 0, len(segs))
	for _, seg := range segs {
		if seg.max.Before(cutoff) {
			candidates = append(candidates, seg)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	slog.Info("usage db compacting 5m to 1h", "segments", len(candidates), "cutoff", cutoff.Format(time.RFC3339))
	agg := map[string]*Bucket{}
	for _, seg := range candidates {
		err := scanBuckets(seg.path, time.Time{}, cutoff, func(b Bucket) {
			start := b.StartAt.UTC().Truncate(time.Hour)
			b.StartAt = start
			b.SlotSeconds = 3600
			mergeBucket(agg, b)
		})
		if err != nil {
			return err
		}
	}
	if err := s.writeRollupBucketsLocked(3600, mapToSortedBuckets(agg)); err != nil {
		return err
	}
	for _, seg := range candidates {
		_ = os.Remove(seg.path)
	}
	slog.Info("usage db compacted 5m to 1h", "segments", len(candidates), "buckets", len(agg))
	return nil
}

func (s *Store) prune1hLocked(now time.Time) error {
	cutoff := now.Add(-s.settings.Rollup1hRetention)
	segs, err := listSegments(filepath.Join(s.dir, "rollup", "3600"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	pruned := 0
	for _, seg := range segs {
		if seg.max.Before(cutoff) {
			_ = os.Remove(seg.path)
			pruned++
		}
	}
	if pruned > 0 {
		slog.Info("usage db pruned 1h rollups", "segments", pruned, "cutoff", cutoff.Format(time.RFC3339))
	}
	return nil
}

func (s *Store) openRawWriterLocked(ts time.Time) error {
	hourDir := filepath.Join(s.dir, "raw", ts.Format("2006"), ts.Format("01"), ts.Format("02"), ts.Format("15"))
	if s.rawWriter != nil && s.rawWriterDir == hourDir {
		return nil
	}
	if err := s.closeRawWriterLocked(); err != nil {
		return err
	}
	w, err := newSegmentWriter(hourDir)
	if err != nil {
		return err
	}
	s.rawWriter = w
	s.rawWriterDir = hourDir
	return nil
}

func (s *Store) closeRawWriterLocked() error {
	if s.rawWriter == nil {
		return nil
	}
	err := s.rawWriter.close()
	s.rawWriter = nil
	s.rawWriterDir = ""
	return err
}

func newSegmentWriter(dir string) (*segmentWriter, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	seq := time.Now().UTC().UnixNano()
	tmp := filepath.Join(dir, fmt.Sprintf("open-%d.jsonl.zst.tmp", seq))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	enc, err := zstd.NewWriter(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &segmentWriter{pathTmp: tmp, dir: dir, seq: seq, file: f, enc: enc, openedAt: time.Now().UTC()}, nil
}

func (w *segmentWriter) writeLine(line []byte, ts time.Time) error {
	if _, err := w.enc.Write(line); err != nil {
		return err
	}
	if _, err := w.enc.Write([]byte("\n")); err != nil {
		return err
	}
	if w.minTs.IsZero() || ts.Before(w.minTs) {
		w.minTs = ts
	}
	if w.maxTs.IsZero() || ts.After(w.maxTs) {
		w.maxTs = ts
	}
	w.count++
	w.bytesIn += int64(len(line) + 1)
	return nil
}

func (w *segmentWriter) shouldRotate(_ int64, maxAge time.Duration) bool {
	if w == nil {
		return false
	}
	if maxAge > 0 && time.Since(w.openedAt) >= maxAge {
		return true
	}
	return false
}

func (w *segmentWriter) close() error {
	if w == nil {
		return nil
	}
	if w.enc != nil {
		_ = w.enc.Close()
	}
	if w.file != nil {
		_ = w.file.Close()
	}
	if w.count == 0 {
		_ = os.Remove(w.pathTmp)
		return nil
	}
	minUnix := w.minTs.UTC().Unix()
	maxUnix := w.maxTs.UTC().Unix()
	final := filepath.Join(w.dir, fmt.Sprintf("%d-%d-%d.jsonl.zst", minUnix, maxUnix, w.seq))
	return os.Rename(w.pathTmp, final)
}

func (s *Store) writeRollupBucketsLocked(slotSeconds int, buckets []Bucket) error {
	if len(buckets) == 0 {
		return nil
	}
	byDay := map[string][]Bucket{}
	for _, b := range buckets {
		day := b.StartAt.UTC().Format("2006/01/02")
		byDay[day] = append(byDay[day], b)
	}
	for day, items := range byDay {
		dir := filepath.Join(s.dir, "rollup", strconv.Itoa(slotSeconds), day)
		w, err := newSegmentWriter(dir)
		if err != nil {
			return err
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].StartAt.Equal(items[j].StartAt) {
				return items[i].Provider < items[j].Provider
			}
			return items[i].StartAt.Before(items[j].StartAt)
		})
		for _, b := range items {
			line, err := json.Marshal(b)
			if err != nil {
				_ = w.close()
				return err
			}
			if err := w.writeLine(line, b.StartAt); err != nil {
				_ = w.close()
				return err
			}
		}
		if err := w.close(); err != nil {
			return err
		}
	}
	return nil
}

func listSegments(root string) ([]segmentMeta, error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, os.ErrNotExist
	}
	out := []segmentMeta{}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".jsonl.zst") || strings.HasPrefix(name, "open-") {
			return nil
		}
		parts := strings.Split(strings.TrimSuffix(name, ".jsonl.zst"), "-")
		if len(parts) < 3 {
			return nil
		}
		minUnix, err1 := strconv.ParseInt(parts[0], 10, 64)
		maxUnix, err2 := strconv.ParseInt(parts[1], 10, 64)
		if err1 != nil || err2 != nil {
			return nil
		}
		out = append(out, segmentMeta{path: path, min: time.Unix(minUnix, 0).UTC(), max: time.Unix(maxUnix, 0).UTC()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].min.Equal(out[j].min) {
			return out[i].path < out[j].path
		}
		return out[i].min.Before(out[j].min)
	})
	return out, nil
}

func scanEvents(path string, from, to time.Time, fn func(Event)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		return err
	}
	defer zr.Close()
	sc := bufio.NewScanner(zr)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 2<<20)
	for sc.Scan() {
		line := bytesTrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var evt Event
		if err := json.Unmarshal(line, &evt); err != nil {
			continue
		}
		ts := evt.Timestamp.UTC()
		if !from.IsZero() && ts.Before(from) {
			continue
		}
		if !to.IsZero() && !ts.Before(to) {
			continue
		}
		fn(evt)
	}
	return sc.Err()
}

func scanBuckets(path string, from, to time.Time, fn func(Bucket)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		return err
	}
	defer zr.Close()
	sc := bufio.NewScanner(zr)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 2<<20)
	for sc.Scan() {
		line := bytesTrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var b Bucket
		if err := json.Unmarshal(line, &b); err != nil {
			continue
		}
		ts := b.StartAt.UTC()
		if !from.IsZero() && ts.Before(from) {
			continue
		}
		if !to.IsZero() && !ts.Before(to) {
			continue
		}
		if b.SlotSeconds <= 0 {
			b.SlotSeconds = usageBucketSizeSeconds()
		}
		fn(b)
	}
	return sc.Err()
}

func (s *Store) importLegacyIfNeeded() {
	if strings.TrimSpace(s.legacyPath) == "" {
		return
	}
	statePath := filepath.Join(s.dir, "meta", "import-state.json")
	if _, err := os.Stat(statePath); err == nil {
		slog.Debug("usage db legacy import skipped", "reason", "already imported")
		return
	}
	b, err := os.ReadFile(s.legacyPath)
	if err != nil || len(b) == 0 {
		return
	}
	slog.Info("usage db importing legacy stats", "path", s.legacyPath)
	var old legacyStatsFile
	if err := json.Unmarshal(b, &old); err != nil || old.Version != 1 || len(old.Buckets) == 0 {
		slog.Warn("usage db legacy import skipped", "reason", "invalid legacy payload")
		return
	}
	items := make([]Bucket, 0, len(old.Buckets))
	for _, bk := range old.Buckets {
		items = append(items, Bucket{
			StartAt:          bk.StartAt.UTC(),
			SlotSeconds:      300,
			Provider:         bk.Provider,
			Model:            bk.Model,
			ClientType:       strings.TrimSpace(bk.ClientType),
			UserAgent:        strings.TrimSpace(bk.UserAgent),
			ClientIP:         strings.TrimSpace(bk.ClientIP),
			APIKeyName:       strings.TrimSpace(bk.APIKeyName),
			Requests:         bk.Requests,
			PromptTokens:     bk.PromptTokens,
			PromptCached:     bk.PromptCached,
			CompletionTokens: bk.CompletionTokens,
			TotalTokens:      bk.TotalTokens,
			LatencyMSSum:     bk.LatencyMSSum,
			PromptTPSSum:     bk.PromptTPSSum,
			GenerationTPSSum: bk.GenerationTPSSum,
		})
	}
	_ = os.MkdirAll(filepath.Dir(statePath), 0o700)
	if err := s.writeRollupBucketsLocked(300, items); err != nil {
		slog.Warn("usage db legacy import failed", "error", err)
		return
	}
	state := importState{Version: 1, ImportedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if out, err := json.MarshalIndent(state, "", "  "); err == nil {
		_ = os.WriteFile(statePath, out, 0o600)
	}
	slog.Info("usage db legacy import completed", "buckets", len(items))
}

func mapToSortedBuckets(m map[string]*Bucket) []Bucket {
	out := make([]Bucket, 0, len(m))
	for _, b := range m {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartAt.Equal(out[j].StartAt) {
			if out[i].Provider == out[j].Provider {
				return out[i].Model < out[j].Model
			}
			return out[i].Provider < out[j].Provider
		}
		return out[i].StartAt.Before(out[j].StartAt)
	})
	return out
}

func mergeBucket(dst map[string]*Bucket, b Bucket) {
	k := bucketKey(b.StartAt, b.Provider, b.Model, b.ClientType, b.UserAgent, b.ClientIP, b.APIKeyName)
	x := dst[k]
	if x == nil {
		c := b
		dst[k] = &c
		return
	}
	x.Requests += b.Requests
	x.FailedRequests += b.FailedRequests
	x.PromptTokens += b.PromptTokens
	x.PromptCached += b.PromptCached
	x.CompletionTokens += b.CompletionTokens
	x.TotalTokens += b.TotalTokens
	x.LatencyMSSum += b.LatencyMSSum
	x.PromptTPSSum += b.PromptTPSSum
	x.GenerationTPSSum += b.GenerationTPSSum
}

func eventToBucket(e Event, slot time.Duration) Bucket {
	start := e.Timestamp.UTC().Truncate(slot)
	return Bucket{
		StartAt:          start,
		SlotSeconds:      int(slot.Seconds()),
		Provider:         e.Provider,
		Model:            e.Model,
		ClientType:       strings.TrimSpace(e.ClientType),
		UserAgent:        strings.TrimSpace(e.UserAgent),
		ClientIP:         strings.TrimSpace(e.ClientIP),
		APIKeyName:       strings.TrimSpace(e.APIKeyName),
		Requests:         1,
		FailedRequests:   failedRequestsFromStatus(e.StatusCode),
		PromptTokens:     e.PromptTokens,
		PromptCached:     e.PromptCached,
		CompletionTokens: e.CompletionToks,
		TotalTokens:      e.TotalTokens,
		LatencyMSSum:     e.LatencyMS,
		PromptTPSSum:     e.PromptTPS,
		GenerationTPSSum: e.GenTPS,
	}
}

func failedRequestsFromStatus(code int) int {
	if code >= 400 {
		return 1
	}
	return 0
}

func bucketKey(start time.Time, provider, model, clientType, userAgent, clientIP, apiKeyName string) string {
	return start.UTC().Format(time.RFC3339) + "|" + provider + "|" + model + "|" + strings.TrimSpace(clientType) + "|" + strings.TrimSpace(userAgent) + "|" + strings.TrimSpace(clientIP) + "|" + strings.TrimSpace(apiKeyName)
}

func overlaps(segMin, segMax, from, to time.Time) bool {
	if !to.IsZero() && !segMin.Before(to) {
		return false
	}
	if !from.IsZero() && segMax.Before(from) {
		return false
	}
	return true
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func usageBucketSizeSeconds() int {
	return int(usageBucketSize.Seconds())
}

func bytesTrimSpace(in []byte) []byte {
	start := 0
	for start < len(in) && (in[start] == ' ' || in[start] == '\n' || in[start] == '\r' || in[start] == '\t') {
		start++
	}
	end := len(in)
	for end > start && (in[end-1] == ' ' || in[end-1] == '\n' || in[end-1] == '\r' || in[end-1] == '\t') {
		end--
	}
	return in[start:end]
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
