#!/usr/bin/env bash
set -euo pipefail

# Auto-restart dev runner:
# - Watches Go/template/assets files for changes.
# - Rebuilds on change.
# - Restarts server only when build succeeds.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

BIN_PATH="${BIN_PATH:-/tmp/openai-personal-proxy-dev}"
POLL_SECONDS="${POLL_SECONDS:-1}"
SERVE_ARGS=("$@")

if [[ ${#SERVE_ARGS[@]} -eq 0 ]]; then
  SERVE_ARGS=("serve")
fi

GOFLAGS_VALUE="${GOFLAGS:-}"
GOCACHE_VALUE="${GOCACHE:-/tmp/go-build}"
GOMODCACHE_VALUE="${GOMODCACHE:-/tmp/go-mod}"
GOPATH_VALUE="${GOPATH:-/tmp/go}"

PID=""
LAST_HASH=""
STOP_TIMEOUT_SECONDS="${STOP_TIMEOUT_SECONDS:-30}"

watch_hash() {
  find cmd pkg -type f \( -name '*.go' -o -name '*.html' -o -name '*.tmpl' -o -name '*.toml' \) -print0 2>/dev/null
  find pkg/assets/files -type f -print0 2>/dev/null
  find . -maxdepth 1 -type f \( -name 'go.mod' -o -name 'go.sum' \) -print0 2>/dev/null
}

compute_hash() {
  local files
  files="$(watch_hash | xargs -0 -r sha256sum | sha256sum | awk '{print $1}')"
  printf '%s' "$files"
}

stop_server() {
  if [[ -n "${PID}" ]] && kill -0 "${PID}" 2>/dev/null; then
    echo "[dev-restart] signaling shutdown pid=${PID} (SIGTERM)"
    kill -TERM "${PID}" 2>/dev/null || true
    local deadline=$((SECONDS + STOP_TIMEOUT_SECONDS))
    while kill -0 "${PID}" 2>/dev/null; do
      if (( SECONDS >= deadline )); then
        echo "[dev-restart] timeout after ${STOP_TIMEOUT_SECONDS}s; force killing pid=${PID}"
        kill -KILL "${PID}" 2>/dev/null || true
        break
      fi
      sleep 1
    done
    wait "${PID}" 2>/dev/null || true
  fi
  PID=""
}

start_server() {
  echo "[dev-restart] starting: ${BIN_PATH} ${SERVE_ARGS[*]}"
  "${BIN_PATH}" "${SERVE_ARGS[@]}" \
    > >(sed -u 's/^/[server] /') \
    2> >(sed -u 's/^/[server] /' >&2) &
  PID=$!
  echo "[dev-restart] running pid=${PID}"
}

rebuild() {
  echo "[dev-restart] building..."
  GOFLAGS="$GOFLAGS_VALUE" \
  GOCACHE="$GOCACHE_VALUE" \
  GOMODCACHE="$GOMODCACHE_VALUE" \
  GOPATH="$GOPATH_VALUE" \
  go build -o "$BIN_PATH" ./cmd/openai-personal-proxy
}

cleanup() {
  stop_server
}
trap cleanup EXIT INT TERM

# Initial build/start.
if rebuild; then
  start_server
else
  echo "[dev-restart] initial build failed; waiting for changes"
fi

LAST_HASH="$(compute_hash)"

echo "[dev-restart] watching for changes every ${POLL_SECONDS}s..."

while true; do
  sleep "$POLL_SECONDS"
  CURRENT_HASH="$(compute_hash)"
  if [[ "$CURRENT_HASH" == "$LAST_HASH" ]]; then
    continue
  fi
  LAST_HASH="$CURRENT_HASH"

  echo "[dev-restart] change detected"
  if rebuild; then
    stop_server
    start_server
  else
    echo "[dev-restart] build failed; server unchanged"
  fi
 done
