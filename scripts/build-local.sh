#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"

mkdir -p "${DIST_DIR}"

echo "[build-local] building torod for darwin/arm64"
(
  cd "${ROOT_DIR}"
  GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o "${DIST_DIR}/torod" ./cmd/torod
)

echo "[build-local] building toro for darwin/arm64"
(
  cd "${ROOT_DIR}"
  GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o "${DIST_DIR}/toro" ./cmd/toro
)

echo "[build-local] binaries available in ${DIST_DIR}"
