#!/bin/sh
set -eu

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  if [ "${TOKENROUTER_ENABLE:-0}" = "1" ]; then
    systemctl enable --now tokenrouter.service || true
  fi
fi
