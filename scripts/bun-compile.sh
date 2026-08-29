#!/usr/bin/env bash
# bun-compile.sh — produce a self-contained 0sec binary via `bun build --compile`.
#
# Usage:
#   scripts/bun-compile.sh                    # compile for the host platform
#   scripts/bun-compile.sh bun-linux-x64      # cross-compile for a specific target
#   scripts/bun-compile.sh bun-darwin-arm64 ./dist-bin/0sec-darwin-arm64
#
# Must be run from the repo root. Assumes pnpm install + pnpm -r build have
# already run (workspace packages need their dist/ directories so Bun can
# resolve @0sec/shared etc.).
#
# Externals are chosen to match the runtime pattern in the source:
#   - playwright / playwright-core / electron / chromium-bidi  — loaded via
#     try/catch dynamic import in racing.ts / oracles.ts / egats.ts. Safe to
#     skip at compile time; runtime gracefully degrades when absent.
#   - bun:ffi                                                  — only resolved
#     on Bun at runtime anyway; no compile-time resolver exists.
#   - sharp                                                    — optional peer
#     of opentui's @opentui/core; not exercised by 0sec code paths.
#   - node-sqlite3-wasm                                        — belt-and-
#     suspenders pairing with the lazy `createRequire` in wasm-shim.ts. The
#     Bun runtime always uses bun:sqlite via createBunEngine; the WASM
#     branch is dead code in the compiled binary. Marking it external
#     prevents Bun from baking node-sqlite3-wasm.wasm (and its absolute
#     `__dirname` path) into the binary, which is what crashed v0.10.1
#     with `ENOENT … node-sqlite3-wasm.wasm` on user machines.

set -euo pipefail
ROOT_DIR="$(pwd -P)"


TARGET="${1:-}"
OUTFILE="${2:-dist-bin/0sec}"

mkdir -p "$(dirname "$OUTFILE")"

if [ -n "$TARGET" ]; then
  TARGET_ARG="--target=$TARGET"
  NATIVE_TARGET="${TARGET#bun-}"
  # Append target suffix to default outfile if caller didn't override
  if [ "$OUTFILE" = "dist-bin/0sec" ]; then
    OUTFILE="dist-bin/0sec-${TARGET#bun-}"
  fi
else
  TARGET_ARG=""
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64|Linux-amd64) NATIVE_TARGET="linux-x64" ;;
    Linux-aarch64|Linux-arm64) NATIVE_TARGET="linux-arm64" ;;
    Darwin-arm64) NATIVE_TARGET="darwin-arm64" ;;
    Darwin-x86_64) NATIVE_TARGET="darwin-x64" ;;
    MINGW*-x86_64|MSYS*-x86_64) NATIVE_TARGET="win32-x64" ;;
    MINGW*-aarch64|MSYS*-aarch64) NATIVE_TARGET="win32-arm64" ;;
    *) echo "Unsupported native target: $(uname -s)-$(uname -m)" >&2; exit 2 ;;
  esac
fi

case "$NATIVE_TARGET" in
  linux-x64|linux-arm64|darwin-arm64|darwin-x64|win32-x64|win32-arm64) ;;
  *) echo "Unsupported compiled target: $NATIVE_TARGET" >&2; exit 2 ;;
esac

# Pull the version from the root package.json so `--version` on the
# compiled binary reports the actual release instead of constants.ts's
# fallback ("0.0.0-dev") — the fallback reads a package.json path that
# isn't in the /$bunfs virtual tree.
PKG_VERSION="$(node -p "require('./package.json').version")"

# `node-gyp-build` hides native addon paths behind a runtime lookup. Stage the
# selected pair at fixed relative paths so c-dataflow's direct requires make Bun
# embed them. The trap leaves normal source builds free of generated binaries.
STAGE_DIR="${ROOT_DIR}/packages/core/dist/stages/tree-sitter-compiled"
node scripts/stage-tree-sitter-native.mjs "$NATIVE_TARGET" "$STAGE_DIR"
trap 'rm -rf "$STAGE_DIR"' EXIT

cd packages/cli

bun build src/index.ts \
  --compile \
  ${TARGET_ARG} \
  --outfile "../../$OUTFILE" \
  --define "__0SEC_VERSION__=\"$PKG_VERSION\"" \
  --define "__0SEC_COMPILED_TARGET__=\"$NATIVE_TARGET\"" \
  --external playwright \
  --external playwright-core \
  --external electron \
  --external chromium-bidi \
  --external bun:ffi \
  --external sharp \
  --external node-sqlite3-wasm \
  --external pdfkit

echo "Built $OUTFILE (version $PKG_VERSION)"
