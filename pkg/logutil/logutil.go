package logutil

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	log "github.com/charmbracelet/log"
)

var (
	outputMu   sync.Mutex
	outputTee  io.Writer
	stderrSink = &stderrLevelFilterWriter{minLevel: log.InfoLevel}
)

func Configure(levelRaw string) error {
	levelRaw = strings.TrimSpace(levelRaw)
	if levelRaw == "" {
		levelRaw = "info"
	}
	level, err := parseConfiguredLevel(levelRaw)
	if err != nil {
		return err
	}
	outputMu.Lock()
	stderrSink.minLevel = level
	outputMu.Unlock()
	// Keep raw logs flowing at all levels; CLI filtering is handled in output sink.
	log.SetLevel(log.DebugLevel)
	applyOutputLocked()
	return nil
}

func parseConfiguredLevel(levelRaw string) (log.Level, error) {
	switch strings.ToLower(strings.TrimSpace(levelRaw)) {
	case "trace", "trac":
		// The logger has no native trace enum; map trace to most verbose mode.
		return log.DebugLevel, nil
	default:
		level, err := log.ParseLevel(levelRaw)
		if err != nil {
			return 0, fmt.Errorf("invalid loglevel %q", levelRaw)
		}
		return level, nil
	}
}

func SetOutputTee(w io.Writer) {
	outputMu.Lock()
	defer outputMu.Unlock()
	outputTee = w
	applyOutputLocked()
}

func applyOutputLocked() {
	stderrSink.out = os.Stderr
	stderrSink.tee = outputTee
	log.SetOutput(stderrSink)
}

type stderrLevelFilterWriter struct {
	mu       sync.Mutex
	out      io.Writer
	tee      io.Writer
	minLevel log.Level
	buf      []byte
}

func (w *stderrLevelFilterWriter) Write(p []byte) (int, error) {
	if w == nil {
		return len(p), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		idx := bytes.IndexByte(w.buf, '\n')
		if idx < 0 {
			break
		}
		line := append([]byte(nil), w.buf[:idx+1]...)
		w.buf = w.buf[idx+1:]
		w.writeLineLocked(line)
	}
	return len(p), nil
}

func (w *stderrLevelFilterWriter) writeLineLocked(line []byte) {
	if len(line) == 0 {
		return
	}
	if w.tee != nil {
		_, _ = w.tee.Write(line)
	}
	if w.out == nil {
		return
	}
	level := extractLogLevel(string(line))
	if level < w.minLevel {
		return
	}
	_, _ = w.out.Write(line)
}

func extractLogLevel(line string) log.Level {
	u := strings.ToUpper(stripANSI(line))
	normalized := strings.ReplaceAll(u, "\t", " ")
	normalized = " " + normalized + " "
	switch {
	case strings.Contains(normalized, " LEVEL=TRACE "), strings.Contains(normalized, " LEVEL=TRAC "),
		strings.Contains(normalized, " TRACE "), strings.Contains(normalized, " TRAC "),
		strings.HasPrefix(strings.TrimSpace(u), "TRACE "), strings.HasPrefix(strings.TrimSpace(u), "TRAC "):
		// The logger has no native trace enum; classify trace as debug for CLI filtering.
		return log.DebugLevel
	case strings.Contains(normalized, " LEVEL=DEBUG "), strings.Contains(normalized, " LEVEL=DEBU "),
		strings.Contains(normalized, " DEBUG "), strings.Contains(normalized, " DEBU "),
		strings.HasPrefix(strings.TrimSpace(u), "DEBUG "), strings.HasPrefix(strings.TrimSpace(u), "DEBU "):
		return log.DebugLevel
	case strings.Contains(normalized, " LEVEL=INFO "),
		strings.Contains(normalized, " INFO "),
		strings.HasPrefix(strings.TrimSpace(u), "INFO "):
		return log.InfoLevel
	case strings.Contains(normalized, " LEVEL=WARN "), strings.Contains(normalized, " LEVEL=WARNING "),
		strings.Contains(normalized, " WARN "), strings.Contains(normalized, " WARNING "),
		strings.HasPrefix(strings.TrimSpace(u), "WARN "):
		return log.WarnLevel
	case strings.Contains(normalized, " LEVEL=ERROR "), strings.Contains(normalized, " LEVEL=ERRO "),
		strings.Contains(normalized, " ERROR "), strings.Contains(normalized, " ERRO "),
		strings.HasPrefix(strings.TrimSpace(u), "ERROR "), strings.HasPrefix(strings.TrimSpace(u), "ERRO "):
		return log.ErrorLevel
	case strings.Contains(normalized, " LEVEL=FATAL "), strings.Contains(normalized, " LEVEL=FATA "),
		strings.Contains(normalized, " FATAL "), strings.Contains(normalized, " FATA "),
		strings.HasPrefix(strings.TrimSpace(u), "FATAL "), strings.HasPrefix(strings.TrimSpace(u), "FATA "):
		return log.FatalLevel
	default:
		return log.InfoLevel
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
