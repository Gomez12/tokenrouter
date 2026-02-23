# openai-personal-proxy

OpenAI API-compatible proxy server in Go.

## Features

- OpenAI-compatible endpoints:
  - `GET /v1/models`
  - `POST /v1/chat/completions`
  - `POST /v1/completions`
  - `POST /v1/embeddings`
  - `POST /v1/responses`
- Incoming bearer-key authentication.
- Multiple upstream providers with per-provider API keys.
- Dynamic model aggregation across providers.
- Model routing via `provider/model` syntax.
- Admin interface (`/admin`) with Alpine.js:
  - Usage stats (tokens, latency, token/s)
  - Provider CRUD
  - Model refresh action
  - Embedded popular-provider presets
  - Add-provider modal with preset dropdown, `Test`, and `Save`
  - Provider pricing cache indicators (`Priced`, `Pricing Updated`)
- Optional automatic Let's Encrypt TLS via ACME.
- Wizard configuration via Cobra `config` command.

## Layout

- CLI commands: `cmd/`
- All packages: `pkg/`

## Quick start

1. Run server wizard:

```bash
go run ./cmd/openai-personal-proxy config
```

2. Start proxy:

```bash
go run ./cmd/openai-personal-proxy serve
```

If the server config does not exist yet, `serve` starts a first-time TUI wizard and asks whether TLS should be enabled (`Let's Encrypt`) or disabled (plain HTTP).

3. Open admin UI:

```text
http://127.0.0.1:8080/admin
```

You will be redirected to `/admin/login` and can sign in with `admin_api_key` from `config.toml`.

## Dev auto-restart

Use the watcher script to rebuild and restart automatically when code changes, only if the build succeeds:

```bash
./dev-restart.sh
```

Pass through `serve` args if needed:

```bash
./dev-restart.sh serve --config ~/.config/openai-personal-proxy/config.toml
```

## Config paths

- Server config: `~/.config/openai-personal-proxy/config.toml`

## Routing behavior

- Preferred: set model as `provider_name/upstream_model`.
- If model has no prefix, proxy uses `default_provider` when set.
- Otherwise, proxy falls back to the first enabled provider.

## Embedded assets

- Shared embedded asset filesystem lives under `pkg/assets/files/`.
- HTML templates: `pkg/assets/files/templates/*.html`
- Popular providers JSON: `pkg/assets/files/popular-providers.json`
- Admin API endpoint for presets: `GET /admin/api/providers/popular`
- Admin API endpoint for connection test: `POST /admin/api/providers/test`
- Admin API endpoints for pricing cache:
  - `GET /admin/api/pricing`
  - `POST /admin/api/pricing/refresh`

## Pricing Cache

- Local cache path: `~/.cache/openai-personal-proxy/pricing-cache.json`
- Pricing data is fetched from provider `/v1/models` metadata when available.
- Pricing fetch is pluggable (`pkg/pricing`), with provider-specific sources.
- Current provider-specific source: OpenCode Zen pricing parsed from `https://opencode.ai/docs/zen/`.
- Refresh runs in the background every 30 minutes once pricing is first requested.
- Provider-level `last_update` and pricing entries are persisted in the cache file.
