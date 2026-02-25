package logutil

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	log "github.com/charmbracelet/log"
)

var (
	outputMu  sync.Mutex
	outputTee io.Writer
)

func Configure(levelRaw string) error {
	levelRaw = strings.TrimSpace(levelRaw)
	if levelRaw == "" {
		levelRaw = "info"
	}
	level, err := log.ParseLevel(levelRaw)
	if err != nil {
		return fmt.Errorf("invalid loglevel %q", levelRaw)
	}
	log.SetLevel(level)
	applyOutputLocked()
	return nil
}

func SetOutputTee(w io.Writer) {
	outputMu.Lock()
	defer outputMu.Unlock()
	outputTee = w
	applyOutputLocked()
}

func applyOutputLocked() {
	if outputTee == nil {
		log.SetOutput(os.Stderr)
		return
	}
	log.SetOutput(io.MultiWriter(os.Stderr, outputTee))
}
