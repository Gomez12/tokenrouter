#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="${VERSION:-}"
if [[ -z "${VERSION}" ]]; then
  if git describe --tags --abbrev=0 >/dev/null 2>&1; then
    VERSION="$(git describe --tags --abbrev=0)"
  else
    VERSION="dev"
  fi
fi
VERSION="${VERSION#refs/tags/}"

COMMIT="${COMMIT:-$(git rev-parse HEAD 2>/dev/null || true)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
DIRTY="${DIRTY:-false}"

if git diff --quiet >/dev/null 2>&1 && git diff --cached --quiet >/dev/null 2>&1; then
  : # keep default/externally provided DIRTY value
else
  DIRTY="true"
fi

OUT_DIR="${OUT_DIR:-dist}"
rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

PKG_VERSION="github.com/lkarlslund/tokenrouter/pkg/version"
LDFLAGS=(
  "-X ${PKG_VERSION}.Version=${VERSION}"
  "-X ${PKG_VERSION}.Commit=${COMMIT}"
  "-X ${PKG_VERSION}.Date=${BUILD_DATE}"
  "-X ${PKG_VERSION}.Dirty=${DIRTY}"
)
LDFLAGS_JOINED="$(printf '%s ' "${LDFLAGS[@]}")"
LDFLAGS_JOINED="${LDFLAGS_JOINED% }"

PLATFORMS=(
  "linux amd64"
  "linux arm64"
  "darwin amd64"
  "darwin arm64"
  "windows amd64"
  "windows arm64"
)

build_one() {
  local goos="$1"
  local goarch="$2"
  local base="tokenrouter_${VERSION}_${goos}_${goarch}"
  local work="${OUT_DIR}/${base}"
  mkdir -p "${work}"

  local torod_bin="torod"
  local toro_bin="toro"
  if [[ "${goos}" == "windows" ]]; then
    torod_bin="torod.exe"
    toro_bin="toro.exe"
  fi

  echo "[build-release] building ${goos}/${goarch}"
  GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS_JOINED}" -o "${work}/${torod_bin}" ./cmd/torod
  GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS_JOINED}" -o "${work}/${toro_bin}" ./cmd/toro

  cp README.md "${work}/README.md"

  if [[ "${goos}" == "windows" ]]; then
    (cd "${OUT_DIR}" && zip -q -r "${base}.zip" "${base}")
    rm -rf "${work}"
  else
    tar -C "${OUT_DIR}" -czf "${OUT_DIR}/${base}.tar.gz" "${base}"
    rm -rf "${work}"
  fi
}

for p in "${PLATFORMS[@]}"; do
  build_one ${p}
done

(
  cd "${OUT_DIR}"
  sha256sum *.tar.gz *.zip > checksums.txt
)

echo "[build-release] artifacts:"
ls -1 "${OUT_DIR}"

