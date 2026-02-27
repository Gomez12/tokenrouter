package proxy

import (
	"html/template"
	"log/slog"
	"sync"

	"github.com/lkarlslund/tokenrouter/pkg/assets"
)

var (
	templatesOnce        sync.Once
	templates            *template.Template
	templatesInitErr     error
	popularProvidersOnce sync.Once
	popularProviders     []assets.PopularProvider
	popularProvidersErr  error
)

func getTemplates() (*template.Template, error) {
	templatesOnce.Do(func() {
		templates, templatesInitErr = assets.ParseTemplates()
	})
	return templates, templatesInitErr
}

func getPopularProviders() ([]assets.PopularProvider, error) {
	popularProvidersOnce.Do(func() {
		popularProviders, popularProvidersErr = assets.LoadPopularProviders()
		if popularProvidersErr != nil {
			slog.Warn("failed to load embedded popular providers", "error", popularProvidersErr)
		}
	})
	return popularProviders, popularProvidersErr
}
