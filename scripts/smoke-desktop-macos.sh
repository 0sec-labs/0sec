#!/usr/bin/env bash
# Smoke the bytes that electron-builder placed inside the macOS application.
# This deliberately starts the Bun dashboard sidecar, not Electron itself: a
# self-hosted runner can run as a launchd service without a logged-in Aqua
# session, while the physical Mac-mini UI smoke is an explicit SSH operation.
set -euo pipefail

APP_BUNDLE="${1:-packages/desktop/release/mac-arm64/0sec.app}"
RESOURCES_DIR="$APP_BUNDLE/Contents/Resources"
SIDECAR="$RESOURCES_DIR/sidecars/0sec-darwin-arm64"
DASHBOARD="$RESOURCES_DIR/dashboard"
READY_LOG="$(mktemp "${TMPDIR:-/tmp}/0sec-desktop-ready.XXXXXX")"
PID=""

cleanup() {
  if [ -n "$PID" ]; then
    kill -TERM "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -f "$READY_LOG"
}
trap cleanup EXIT

test -x "$SIDECAR"
test -f "$DASHBOARD/index.html"

"$SIDECAR" dashboard \
  --no-open \
  --host 127.0.0.1 \
  --port 0 \
  --asset-dir "$DASHBOARD" \
  --ready-json >"$READY_LOG" 2>&1 &
PID=$!

URL=""
attempt=0
while [ "$attempt" -lt 80 ]; do
  URL="$(node -e '
const fs = require("node:fs");
const lines = fs.readFileSync(process.argv[1], "utf8").split("\n");
for (const line of lines) {
  if (!line.startsWith("0SEC_DASHBOARD_READY ")) continue;
  try {
    const value = JSON.parse(line.slice("0SEC_DASHBOARD_READY ".length));
    if (typeof value.url === "string") process.stdout.write(value.url);
  } catch {}
}
' "$READY_LOG")"
  if [ -n "$URL" ]; then
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.25
done

test -n "$URL"
curl --fail --silent --show-error "$URL/dashboard" >/dev/null
printf 'macOS desktop sidecar smoke passed: %s\n' "$URL"
