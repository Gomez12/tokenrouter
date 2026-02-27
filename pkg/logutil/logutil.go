package logutil

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/charmbracelet/lipgloss"
)

var (
	outputMu   sync.Mutex
	outputTee  io.Writer
	stderrSink = &stderrLevelFilterWriter{minLevel: slog.LevelInfo}
	debugStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	infoStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	warnStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	errorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
)

func init() {
	applyOutputLocked()
}

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
	applyOutputLocked()
	return nil
}

func parseConfiguredLevel(levelRaw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(levelRaw)) {
	case "trace", "trac":
		return slog.LevelDebug, nil
	case "debug", "debu":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error", "erro":
		return slog.LevelError, nil
	case "fatal", "fata":
		// slog has no fatal; treat as error-level filtering.
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid loglevel %q", levelRaw)
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
	colorize := isColorEnabled()
	var out io.Writer = stderrSink
	if colorize {
		out = &ansiUnescapeWriter{out: out}
	}
	h := slog.NewTextHandler(out, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if !colorize {
				return a
			}
			if a.Key == slog.LevelKey {
				level := strings.ToUpper(strings.TrimSpace(a.Value.String()))
				return slog.String(slog.LevelKey, colorizeLevel(level))
			}
			return a
		},
	})
	slog.SetDefault(slog.New(h))
}

type stderrLevelFilterWriter struct {
	mu       sync.Mutex
	out      io.Writer
	tee      io.Writer
	minLevel slog.Level
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

func extractLogLevel(line string) slog.Level {
	u := strings.ToUpper(stripANSI(line))
	normalized := strings.ReplaceAll(u, "\t", " ")
	normalized = " " + normalized + " "
	switch {
	case strings.Contains(normalized, " LEVEL=TRACE "), strings.Contains(normalized, " LEVEL=TRAC "),
		strings.Contains(normalized, " TRACE "), strings.Contains(normalized, " TRAC "),
		strings.HasPrefix(strings.TrimSpace(u), "TRACE "), strings.HasPrefix(strings.TrimSpace(u), "TRAC "):
		return slog.LevelDebug
	case strings.Contains(normalized, " LEVEL=DEBUG "), strings.Contains(normalized, " LEVEL=DEBU "),
		strings.Contains(normalized, " DEBUG "), strings.Contains(normalized, " DEBU "),
		strings.HasPrefix(strings.TrimSpace(u), "DEBUG "), strings.HasPrefix(strings.TrimSpace(u), "DEBU "):
		return slog.LevelDebug
	case strings.Contains(normalized, " LEVEL=INFO "),
		strings.Contains(normalized, " INFO "),
		strings.HasPrefix(strings.TrimSpace(u), "INFO "):
		return slog.LevelInfo
	case strings.Contains(normalized, " LEVEL=WARN "), strings.Contains(normalized, " LEVEL=WARNING "),
		strings.Contains(normalized, " WARN "), strings.Contains(normalized, " WARNING "),
		strings.HasPrefix(strings.TrimSpace(u), "WARN "):
		return slog.LevelWarn
	case strings.Contains(normalized, " LEVEL=ERROR "), strings.Contains(normalized, " LEVEL=ERRO "),
		strings.Contains(normalized, " ERROR "), strings.Contains(normalized, " ERRO "),
		strings.HasPrefix(strings.TrimSpace(u), "ERROR "), strings.HasPrefix(strings.TrimSpace(u), "ERRO "):
		return slog.LevelError
	case strings.Contains(normalized, " LEVEL=FATAL "), strings.Contains(normalized, " LEVEL=FATA "),
		strings.Contains(normalized, " FATAL "), strings.Contains(normalized, " FATA "),
		strings.HasPrefix(strings.TrimSpace(u), "FATAL "), strings.HasPrefix(strings.TrimSpace(u), "FATA "):
		return slog.LevelError
	default:
		return slog.LevelInfo
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

func isColorEnabled() bool {
	if isTruthyEnv("CLICOLOR_FORCE") || isTruthyEnv("FORCE_COLOR") {
		return true
	}
	if strings.TrimSpace(os.Getenv("NO_COLOR")) != "" {
		return false
	}
	if strings.TrimSpace(os.Getenv("CLICOLOR")) == "0" {
		return false
	}
	return true
}

func isTruthyEnv(key string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func colorizeLevel(level string) string {
	switch level {
	case "DEBUG":
		return debugStyle.Render(level)
	case "INFO":
		return infoStyle.Render(level)
	case "WARN":
		return warnStyle.Render(level)
	case "ERROR":
		return errorStyle.Render(level)
	default:
		return level
	}
}

type ansiUnescapeWriter struct {
	out io.Writer
}

func (w *ansiUnescapeWriter) Write(p []byte) (int, error) {
	if w == nil || w.out == nil {
		return len(p), nil
	}
	line := string(p)
	line = strings.ReplaceAll(line, `\x1b[`, "\x1b[")
	return w.out.Write([]byte(line))
}
