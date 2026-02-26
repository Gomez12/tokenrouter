package proxy

import (
	"path/filepath"
	"testing"
)

func isolateDefaultDataPaths(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
}
