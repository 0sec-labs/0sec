#!/usr/bin/env bash
#
# run-recency-flywheel.sh — the daily RECENCY FLYWHEEL driver (bench).
#
# Fetches fresh linux-next, then runs `0sec recency-hunt` over the last N hours
# and writes a dated JSON + markdown report. ADDITIVE and NON-DISRUPTIVE: it only
# fetches /root/linux-next (the snapshot repo — NOT the KASAN/kmsan build trees
# under /root/next-recency or /root/kernel-objects) and runs one CLI process at
# idle priority. It never touches the KCSAN/AIO fuzzer, the kmsan QEMUs, or
# /root/cp*.
#
# Env overrides (all optional):
#   RECENCY_TREE      kernel tree to hunt          (default /root/linux-next)
#   RECENCY_HOURS     freshness window in hours    (default 24)
#   RECENCY_ENGINE    built 0sec engine dir      (default /root/0sec-recency-flywheel)
#   RECENCY_REPORTS   dated report output dir      (default /root/recency-flywheel/reports)
#   RECENCY_MODELS    per-file invariant models    (default /root/recency-flywheel/models)
#   RECENCY_RUNTIME   engine runtime               (default codex — uses /root/.codex/auth.json)
#   RECENCY_MAX_CLASSIFY  cap in-scope files sent to the LLM classifier (default 80)
#   RECENCY_MAX_HUNT      cap semantic files run through the engine       (default 12)
#   RECENCY_FINDER_TIMEOUT_MS  per-finder wall-clock cap (default 420000 = 7m; the
#                              stock 240000 is too tight for cold kernel-file finders)
#
# Exit code is the CLI's own: 0=survivor lead(s), 1=none, 2=empty window, 3=error.
set -uo pipefail

TREE="${RECENCY_TREE:-/root/linux-next}"
HOURS="${RECENCY_HOURS:-24}"
ENGINE="${RECENCY_ENGINE:-/root/0sec-recency-flywheel}"
REPORTS="${RECENCY_REPORTS:-/root/recency-flywheel/reports}"
MODELS="${RECENCY_MODELS:-/root/recency-flywheel/models}"
RUNTIME="${RECENCY_RUNTIME:-codex}"
MAX_CLASSIFY="${RECENCY_MAX_CLASSIFY:-80}"
MAX_HUNT="${RECENCY_MAX_HUNT:-12}"
export HUNT_FINDER_TIMEOUT_MS="${RECENCY_FINDER_TIMEOUT_MS:-420000}"

mkdir -p "$REPORTS" "$MODELS"

echo "[recency-flywheel] $(date -Is) start tree=$TREE hours=$HOURS"

# 1) Refresh linux-next (fetch only — never checkout/rebase; a shallow deepen is
#    enough to give the range a few days of history). A fetch failure is a WARN,
#    not fatal: we can still hunt the currently-checked-out window.
if [ -d "$TREE/.git" ]; then
  git -C "$TREE" fetch --depth=400 origin >/dev/null 2>&1 \
    && echo "[recency-flywheel] fetched linux-next ($(git -C "$TREE" log -1 --format='%h %ci'))" \
    || echo "[recency-flywheel] WARN: linux-next fetch failed; hunting current checkout"
else
  echo "[recency-flywheel] WARN: $TREE is not a git tree; hunting as-is"
fi

# 2) Run the flywheel. --report-dir writes <REPORTS>/YYYY-MM-DD.{json,md} and
#    logs a one-line funnel summary to stdout (captured by journald).
cd "$ENGINE" || { echo "[recency-flywheel] FATAL: engine dir $ENGINE missing"; exit 3; }
node packages/cli/dist/index.js recency-hunt \
  --tree "$TREE" \
  --hours "$HOURS" \
  --runtime "$RUNTIME" \
  --max-classify-files "$MAX_CLASSIFY" \
  --max-hunt-files "$MAX_HUNT" \
  --model-dir "$MODELS" \
  --report-dir "$REPORTS"
rc=$?

echo "[recency-flywheel] $(date -Is) done rc=$rc"
exit $rc
