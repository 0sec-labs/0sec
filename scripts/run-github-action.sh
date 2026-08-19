#!/usr/bin/env bash
set -euo pipefail

MODE="${INPUT_MODE:-review}"
PATH_INPUT="${INPUT_PATH:-.}"
PACKAGE_INPUT="${INPUT_PACKAGE:-}"
TARGET_INPUT="${INPUT_TARGET:-}"
SCAN_MODE="${INPUT_SCAN_MODE:-probe}"
DEPTH="${INPUT_DEPTH:-default}"
RUNTIME="${INPUT_RUNTIME:-api}"
TIMEOUT="${INPUT_TIMEOUT:-300000}"
PRIMARY_FORMAT="${INPUT_FORMAT:-json}"
SEVERITY_THRESHOLD="${INPUT_SEVERITY_THRESHOLD:-high}"
COUNT_THRESHOLD="${INPUT_THRESHOLD:-0}"
REPORT_DIR="${INPUT_REPORT_DIR:-pwnkit-report}"

case "$MODE" in
  review|audit|scan) ;;
  *)
    echo "::error::Invalid mode '$MODE'. Expected review, audit, or scan."
    exit 1
    ;;
esac

case "$DEPTH" in
  quick|default|deep) ;;
  *)
    echo "::error::Invalid depth '$DEPTH'. Expected quick, default, or deep."
    exit 1
    ;;
esac

case "$RUNTIME" in
  api|claude|codex|gemini|auto) ;;
  *)
    echo "::error::Invalid runtime '$RUNTIME'. Expected api, claude, codex, gemini, or auto."
    exit 1
    ;;
esac

case "$SCAN_MODE" in
  probe|deep|mcp|web) ;;
  *)
    echo "::error::Invalid scan-mode '$SCAN_MODE'. Expected probe, deep, mcp, or web."
    exit 1
    ;;
esac

case "$PRIMARY_FORMAT" in
  json|sarif) ;;
  *)
    echo "::error::Invalid format '$PRIMARY_FORMAT'. Expected json or sarif."
    exit 1
    ;;
esac

case "$SEVERITY_THRESHOLD" in
  critical|high|medium|low|info|none) ;;
  *)
    echo "::error::Invalid severity-threshold '$SEVERITY_THRESHOLD'. Expected critical, high, medium, low, info, or none."
    exit 1
    ;;
esac

if [[ ! "$TIMEOUT" =~ ^[0-9]+$ ]]; then
  echo "::error::Invalid timeout '$TIMEOUT'. Expected an integer number of milliseconds."
  exit 1
fi

if [[ ! "$COUNT_THRESHOLD" =~ ^[0-9]+$ ]]; then
  echo "::error::Invalid threshold '$COUNT_THRESHOLD'. Expected a non-negative integer."
  exit 1
fi

mkdir -p "$REPORT_DIR"
JSON_REPORT="$REPORT_DIR/report.json"
SARIF_REPORT="$REPORT_DIR/report.sarif"
STDERR_LOG="$REPORT_DIR/pwnkit.stderr.log"

COMMON_ARGS=(
  --depth "$DEPTH"
  --format json
  --runtime "$RUNTIME"
  --timeout "$TIMEOUT"
)

case "$MODE" in
  review)
    if [[ -z "$PATH_INPUT" || ! -e "$PATH_INPUT" ]]; then
      echo "::error::Review path '$PATH_INPUT' does not exist."
      exit 1
    fi
    TARGET_LABEL="$PATH_INPUT"
    COMMAND=(pwnkit-cli review "$PATH_INPUT" "${COMMON_ARGS[@]}")
    ;;
  audit)
    if [[ -z "$PACKAGE_INPUT" ]]; then
      echo "::error::Input 'package' is required when mode=audit."
      exit 1
    fi
    TARGET_LABEL="$PACKAGE_INPUT"
    COMMAND=(pwnkit-cli audit "$PACKAGE_INPUT" "${COMMON_ARGS[@]}")
    ;;
  scan)
    if [[ -z "$TARGET_INPUT" ]]; then
      echo "::error::Input 'target' is required when mode=scan."
      exit 1
    fi
    TARGET_LABEL="$TARGET_INPUT"
    COMMAND=(pwnkit-cli scan --target "$TARGET_INPUT" --mode "$SCAN_MODE" "${COMMON_ARGS[@]}")
    ;;
esac

set +e
"${COMMAND[@]}" >"$JSON_REPORT" 2>"$STDERR_LOG"
CLI_EXIT=$?
set -e

if [[ ! -s "$JSON_REPORT" ]]; then
  cat "$STDERR_LOG" >&2 || true
  echo "::error::pwnkit-cli did not produce a JSON report."
  exit ${CLI_EXIT:-1}
fi

if [[ $CLI_EXIT -ne 0 ]]; then
  echo "::warning::pwnkit-cli exited with code $CLI_EXIT but produced a report. Continuing so findings can be surfaced."
fi

ACTION_ROOT="${PWNKIT_ACTION_ROOT:-${GITHUB_ACTION_PATH}}"

node "${ACTION_ROOT}/scripts/render-github-action-output.mjs" \
  "$JSON_REPORT" \
  "$SARIF_REPORT" \
  "$PRIMARY_FORMAT" \
  "$MODE" \
  "$TARGET_LABEL" \
  "$SEVERITY_THRESHOLD" \
  "$COUNT_THRESHOLD"
