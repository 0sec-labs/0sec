#!/usr/bin/env bash
#
# ci-runner-bootstrap.sh — runner bootstrap + cache-integrity preflight for the
# self-hosted PwnKit CI runners (#610). Run once per job, right after
# actions/setup-node, in place of a bare `corepack enable`.
#
# It does three things, all learned the hard way (2026-05-30):
#
# 0. disk-space fail-fast.
#    A titan runner filled its disk and the runner PROCESS itself crashed
#    mid-job with `No space left on device` writing its own _diag log — a
#    cryptic, late failure that also took down an unrelated dashboard
#    boot-smoke the same night (PR #620). Check up front and fail with an
#    actionable message naming the runner, so the operator knows which host to
#    clean instead of chasing a mid-job ENOSPC.
#
# 1. corepack/pnpm via a runner-WRITABLE shim dir.
#    On hosts where the matrix node is system-installed (root-owned /usr) —
#    observed for node 25 on the titan pool — a plain `corepack enable` dies
#    with `EACCES: permission denied, symlink '.../pnpm.js' -> '/usr/bin/pnpm'`
#    because the unprivileged `runner` user can't write the shim into /usr/bin.
#    We install the pnpm shim into a $HOME-local dir and put it on PATH for
#    later steps via $GITHUB_PATH. (Only the `pnpm` shim — not npm/node — so we
#    don't shadow the system npm the smoke jobs use.)
#
# 2. cache-integrity preflight.
#    A 2-byte-truncated `node-sqlite3-wasm.wasm` once got cached in npm's
#    `_cacache` on a colossus runner and was reused deterministically, so every
#    install on that host produced a corrupt wasm -> `WebAssembly.Module()`
#    CompileError ("section ... extends past end of module"). `npm cache verify`
#    re-validates cached content against its integrity hashes and evicts
#    corrupt / garbage-collectable entries, so the next install re-fetches a
#    clean copy. `pnpm store prune` drops orphaned packages from the store.
#    This is best-effort PREVENTION; the guaranteed fail-fast is the
#    wasm-instantiate assertion in install-smoke (assert-sqlite-wasm.mjs).
set -euo pipefail

# ── 0. disk-space fail-fast ──────────────────────────────────────────────────
# Measure the filesystem backing $HOME — where the runner work dir, npm
# _cacache and the pnpm store all live on our self-hosted pool. Fail before
# doing any work if free space is below the floor, so a near-full runner is
# surfaced cleanly instead of crashing mid-install with ENOSPC. Override the
# floor with MIN_FREE_GIB if a job legitimately needs less headroom.
min_free_gib="${MIN_FREE_GIB:-3}"
disk_target="${RUNNER_WORKSPACE:-$HOME}"
avail_kib="$(df -Pk "$disk_target" | awk 'NR==2 {print $4}')"
avail_gib=$(( avail_kib / 1024 / 1024 ))
echo "::group::disk preflight (${disk_target})"
echo "free space: ${avail_gib} GiB (floor ${min_free_gib} GiB, runner ${RUNNER_NAME:-unknown})"
if [ "$avail_gib" -lt "$min_free_gib" ]; then
  echo "::error::runner ${RUNNER_NAME:-unknown} has only ${avail_gib} GiB free on ${disk_target} (< ${min_free_gib} GiB floor). Clean its disk (docker/buildx cache, npm _cacache, pnpm store) before re-running — failing fast to avoid a mid-job ENOSPC crash (#610)."
  exit 1
fi
echo "::endgroup::"

shim_dir="${COREPACK_SHIM_DIR:-$HOME/.corepack-bin}"
mkdir -p "$shim_dir"

echo "::group::corepack enable (writable shim dir: $shim_dir)"
corepack enable --install-directory "$shim_dir" pnpm
corepack prepare pnpm@9 --activate
export PATH="$shim_dir:$PATH"
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$shim_dir" >> "$GITHUB_PATH"
fi
echo "pnpm $(pnpm --version) ready (corepack shim in $shim_dir)"
echo "::endgroup::"

echo "::group::npm cache verify"
# Self-heals integrity-mismatched cache entries (exits 0 even when it reclaims
# corrupt content); a non-zero exit is unexpected, so warn but don't hard-fail.
npm cache verify || echo "::warning::npm cache verify exited non-zero"
echo "::endgroup::"

echo "::group::pnpm store prune"
pnpm store prune || echo "::warning::pnpm store prune exited non-zero"
echo "::endgroup::"
