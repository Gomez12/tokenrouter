package version

import (
	"fmt"
	"runtime/debug"
	"strings"
)

var (
	// These can be set at build time with -ldflags:
	// -X github.com/lkarlslund/tokenrouter/pkg/version.Version=vX.Y.Z
	// -X github.com/lkarlslund/tokenrouter/pkg/version.Commit=<sha>
	// -X github.com/lkarlslund/tokenrouter/pkg/version.Date=<rfc3339>
	// -X github.com/lkarlslund/tokenrouter/pkg/version.Dirty=true
	Version = "dev"
	Commit  = ""
	Date    = ""
	Dirty   = ""
)

type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Date    string `json:"date,omitempty"`
	Dirty   bool   `json:"dirty,omitempty"`
}

func Current() Info {
	info := Info{
		Version: strings.TrimSpace(Version),
		Commit:  strings.TrimSpace(Commit),
		Date:    strings.TrimSpace(Date),
		Dirty:   strings.EqualFold(strings.TrimSpace(Dirty), "true"),
	}
	if info.Version == "" {
		info.Version = "dev"
	}

	// Fallback to embedded VCS info when ldflags are not provided.
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = strings.TrimSpace(s.Value)
				}
			case "vcs.time":
				if info.Date == "" {
					info.Date = strings.TrimSpace(s.Value)
				}
			case "vcs.modified":
				if !info.Dirty {
					info.Dirty = strings.EqualFold(strings.TrimSpace(s.Value), "true")
				}
			}
		}
	}
	return info
}

func String() string {
	v := Current()
	parts := []string{v.Version}
	if v.Commit != "" {
		short := v.Commit
		if len(short) > 12 {
			short = short[:12]
		}
		parts = append(parts, short)
	}
	if v.Dirty {
		parts = append(parts, "dirty")
	}
	return strings.Join(parts, "+")
}

func Detailed(component string) string {
	v := Current()
	if strings.TrimSpace(component) == "" {
		component = "tokenrouter"
	}
	out := fmt.Sprintf("%s %s", component, String())
	if v.Date != "" {
		out += "\nBuilt: " + v.Date
	}
	return out
}
