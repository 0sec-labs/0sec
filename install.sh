#!/usr/bin/env bash
# pwnkit install script.
#
# Detects the host platform, downloads the matching standalone binary from
# the latest GitHub Release, **verifies its SHA-256 against the release's
# published `checksums.txt` manifest**, and drops it into
# $PWNKIT_INSTALL_DIR (default: $HOME/.pwnkit/bin).
#
# One-line install:
#   curl -fsSL https://raw.githubusercontent.com/0sec-labs/pwnkit/main/install.sh | bash
#
# Pin a specific version:
#   curl -fsSL https://raw.githubusercontent.com/0sec-labs/pwnkit/main/install.sh | PWNKIT_VERSION=v0.8.0 bash
#
# Override install directory:
#   curl -fsSL https://raw.githubusercontent.com/0sec-labs/pwnkit/main/install.sh | PWNKIT_INSTALL_DIR=/usr/local/bin bash
#
# Supply-chain integrity (added 2026-05-16):
#   This script refuses to install a binary that doesn't match the
#   SHA-256 manifest (`checksums.txt`) published alongside the release.
#   The manifest is fetched from the same release tag as the binary, so
#   a mismatch indicates either a tampered binary in flight or a
#   compromised release. Either way the install aborts before the file
#   is made executable. See the "Binary integrity" section of SECURITY.md.

set -euo pipefail

REPO="0sec-labs/pwnkit"

red()    { printf '\033[31m%s\033[0m' "$*"; }
green()  { printf '\033[32m%s\033[0m' "$*"; }
yellow() { printf '\033[33m%s\033[0m' "$*"; }
bold()   { printf '\033[1m%s\033[0m' "$*"; }

say()  { printf '%s %s\n' "$(green '[pwnkit]')" "$*"; }
warn() { printf '%s %s\n' "$(yellow '[pwnkit]')" "$*" >&2; }
die()  { printf '%s %s\n' "$(red '[pwnkit]')" "$*" >&2; exit 1; }

# ── Host detection ────────────────────────────────────────────────────────

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64)  ARCH=x64   ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "Unsupported architecture: $ARCH" ;;
esac

case "$OS" in
  linux)  TARGET="linux-${ARCH}"  ;;
  darwin) TARGET="darwin-${ARCH}" ;;
  msys*|mingw*|cygwin*)
    die "Windows detected. Download pwnkit-windows-x64.exe from
       https://github.com/$REPO/releases/latest and add it to your PATH manually."
    ;;
  *) die "Unsupported OS: $OS" ;;
esac

# Intel Mac is intentionally not shipped — Apple stopped selling them in 2022
# and building on GH's macos-13 pool is unreliable. Advise Bun-from-source.
if [ "$TARGET" = "darwin-x64" ]; then
  die "pwnkit does not ship a darwin-x64 binary. Install Bun and build from source:
       curl -fsSL https://bun.sh/install | bash
       git clone https://github.com/$REPO.git
       cd pwnkit && pnpm install --frozen-lockfile && pnpm -r build
       bash scripts/bun-compile.sh
       mv dist-bin/pwnkit ~/.pwnkit/bin/pwnkit"
fi

# ── SHA-256 tool detection ────────────────────────────────────────────────
# GNU coreutils (Linux) ships `sha256sum`. BSD/macOS ships `shasum -a 256`.
# Pick whichever the host has. Both emit "<hex>  <name>" — the same format
# checksums.txt uses, so they're directly comparable.

if command -v sha256sum >/dev/null 2>&1; then
  SHA256_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA256_CMD="shasum -a 256"
else
  die "Neither sha256sum nor shasum is available — cannot verify binary integrity.
       Install GNU coreutils (Linux) or use a host with /usr/bin/shasum (macOS)."
fi

# ── Resolve release tag ───────────────────────────────────────────────────

TAG="${PWNKIT_VERSION:-}"
if [ -z "$TAG" ]; then
  say "Resolving latest release..."
  TAG="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep -m1 '"tag_name"' \
    | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
  [ -n "$TAG" ] || die "Could not determine the latest release. Set PWNKIT_VERSION=vX.Y.Z."
fi

# ── Download ──────────────────────────────────────────────────────────────

INSTALL_DIR="${PWNKIT_INSTALL_DIR:-$HOME/.pwnkit/bin}"
ASSET="pwnkit-${TARGET}"
URL="https://github.com/$REPO/releases/download/${TAG}/${ASSET}"
CHECKSUMS_URL="https://github.com/$REPO/releases/download/${TAG}/checksums.txt"

say "Installing pwnkit $(bold "$TAG") for $(bold "$TARGET")..."
say "  from: $URL"
say "  to:   $INSTALL_DIR/pwnkit"

mkdir -p "$INSTALL_DIR"

TMP="$(mktemp -t pwnkit.XXXXXX)"
CHECKSUMS_TMP="$(mktemp -t pwnkit-checksums.XXXXXX)"
trap 'rm -f "$TMP" "$CHECKSUMS_TMP"' EXIT

# Fetch the checksum manifest BEFORE the binary. If the release is missing
# its manifest (e.g. an old pre-0.11.x tag, or a partially uploaded release)
# we abort here rather than ever writing an unverified binary to disk.
say "Fetching SHA-256 manifest..."
if ! curl -fSL --silent -o "$CHECKSUMS_TMP" "$CHECKSUMS_URL"; then
  die "Could not fetch checksums.txt from $CHECKSUMS_URL
       Refusing to install an unverified binary. If this release pre-dates
       supply-chain hardening (< v0.12.0), pin a newer tag with PWNKIT_VERSION=vX.Y.Z."
fi

# Pull the line for our asset out of the manifest. Match the GNU/BSD shape:
# "<64-hex>  <name>" (text) or "<64-hex> *<name>" (binary). Reject anything
# that doesn't parse to exactly one line, so a malformed or
# unexpectedly-empty manifest can't slip through as a "match".
EXPECTED_HASH="$(grep -E "^[0-9a-fA-F]{64} [ *]${ASSET}$" "$CHECKSUMS_TMP" | head -n1 | awk '{print $1}' || true)"
if [ -z "$EXPECTED_HASH" ]; then
  warn "Manifest contents:"
  sed 's/^/    /' "$CHECKSUMS_TMP" >&2
  die "checksums.txt has no entry for $ASSET — refusing to install."
fi

say "Downloading binary..."
if ! curl -fSL --progress-bar -o "$TMP" "$URL"; then
  die "Download failed. Verify the release exists: https://github.com/$REPO/releases/tag/$TAG"
fi

say "Verifying SHA-256..."
ACTUAL_HASH="$($SHA256_CMD "$TMP" | awk '{print $1}')"
if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
  die "SHA-256 mismatch for $ASSET
       expected: $EXPECTED_HASH
       actual:   $ACTUAL_HASH
       Refusing to install a binary that doesn't match the release manifest.
       This usually means the download was corrupted or tampered with in flight."
fi

say "$(green 'integrity verified')"

# Only NOW make the file executable. A mismatched or unverifiable binary
# never gets the exec bit, so even if a later step somehow ran it
# accidentally, the kernel would refuse.
chmod +x "$TMP"
mv "$TMP" "$INSTALL_DIR/pwnkit"
trap - EXIT
rm -f "$CHECKSUMS_TMP"

# ── Post-install guidance ─────────────────────────────────────────────────

say "Installed to $(bold "$INSTALL_DIR/pwnkit")"

# PATH hint — only nag if the install dir isn't already resolvable.
case ":$PATH:" in
  *:"$INSTALL_DIR":*) ;;
  *)
    echo ""
    warn "$INSTALL_DIR is not in your PATH. Add this line to your shell profile:"
    echo ""
    echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
    echo ""
    warn "Or run pwnkit by its full path: $INSTALL_DIR/pwnkit"
    echo ""
    ;;
esac

say "Try it:"
echo "    pwnkit --version"
echo "    pwnkit scan --target https://example.com --mode web"
