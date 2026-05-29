#!/usr/bin/env bash
#
# ci-runner-bootstrap.sh — runner bootstrap + cache-integrity preflight for the
# self-hosted PwnKit CI runners (#610). Run once per job, right after
# actions/setup-node, in place of a bare `corepack enable`.
#
# It does two things, both learned the hard way (2026-05-30):
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
