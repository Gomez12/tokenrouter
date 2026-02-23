package proxy

import (
	"html/template"
	"log"
	"sync"

	"github.com/lkarlslund/openai-personal-proxy/pkg/assets"
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
			log.Printf("failed to load embedded popular providers: %v", popularProvidersErr)
		}
	})
	return popularProviders, popularProvidersErr
}
