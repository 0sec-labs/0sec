#!/usr/bin/env sh
# Provision the pinned FoxGuard binary for this host architecture.
#
# Downloads the verified release asset from 0sec-labs/foxguard to a configurable
# install directory (default: /usr/local/bin). The pinned version is the same
# FOXGUARD_PINNED_TAG used by the 0sec runtime (v0.13.0).
#
# Usage:
#   bash scripts/provision-foxguard.sh                    # install to /usr/local/bin
#   INSTALL_DIR=/opt/bin bash scripts/provision-foxguard.sh
set -eu

FOXGUARD_REPO="0sec-labs/foxguard"
FOXGUARD_TAG="${FOXGUARD_TAG:-v0.13.0}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# ── v0.13.0 checksums (cross-checked against the release's checksums.txt) ──
# Update the pin and its checksums together when upgrading.
FOXGUARD_SHA256_LINUX_X64="2ddb59b892836c85c38c7b100a3b714c950d04ad4762bd8b606bc7ec1482d000"
FOXGUARD_SHA256_LINUX_ARM64="a0a6bebf632dfe27b8d5a1d0a86c01782424d4cadc1981f6bf5de2649fd298fc"
FOXGUARD_SHA256_MACOS_ARM64="042015d898b2a2de18ac4bba20fe3152ad6d055fe2fdfb7c735449744f9a3f53"
FOXGUARD_SHA256_MACOS_X64="8cc20d138eed0c7a82ce9e23c5dd5574b4b0f27e82ce7ab8c112c15b55dd7288"
FOXGUARD_SHA256_WIN_X64="044d1a3023c5f10266f66125e6c9d019a98888fbc12a07120b66bdd8e6014238"

fail() {
  printf '%s\n' "foxguard provisioner: $*" >&2
  exit 1
}

[ "$FOXGUARD_TAG" = "v0.13.0" ] || fail "update the pinned checksums before selecting another release"

# Resolve platform → asset name + expected sha256
case "$(uname -s)" in
  Darwin)
    case "$(uname -m)" in
      arm64)
        ASSET="foxguard-macos-aarch64"
        EXPECTED_SHA256="$FOXGUARD_SHA256_MACOS_ARM64"
        ;;
      x86_64)
        ASSET="foxguard-macos-x86_64"
        EXPECTED_SHA256="$FOXGUARD_SHA256_MACOS_X64"
        ;;
      *) fail "unsupported macOS architecture: $(uname -m)" ;;
    esac
    ;;
  Linux)
    case "$(uname -m)" in
      x86_64|amd64)
        ASSET="foxguard-linux-x86_64"
        EXPECTED_SHA256="$FOXGUARD_SHA256_LINUX_X64"
        ;;
      aarch64|arm64)
        ASSET="foxguard-linux-aarch64"
        EXPECTED_SHA256="$FOXGUARD_SHA256_LINUX_ARM64"
        ;;
      *) fail "unsupported Linux architecture: $(uname -m)" ;;
    esac
    ;;
  MINGW*|MSYS*)
    case "$(uname -m)" in
      x86_64)
        ASSET="foxguard-windows-x86_64.exe"
        EXPECTED_SHA256="$FOXGUARD_SHA256_WIN_X64"
        ;;
      *) fail "unsupported Windows architecture: $(uname -m)" ;;
    esac
    ;;
  *)
    fail "unsupported operating system: $(uname -s)"
    ;;
esac

command -v curl >/dev/null 2>&1 || fail "curl is required"
if command -v sha256sum >/dev/null 2>&1; then
  sha256_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  fail "sha256sum or shasum is required to verify the download"
fi

DOWNLOAD_URL="https://github.com/${FOXGUARD_REPO}/releases/download/${FOXGUARD_TAG}/${ASSET}"
INSTALL_PATH="${INSTALL_DIR}/foxguard"

# Skip if already installed and matching
if [ -f "$INSTALL_PATH" ] && [ ! -L "$INSTALL_PATH" ]; then
  actual="$(sha256_file "$INSTALL_PATH")"
  if [ "$actual" = "$EXPECTED_SHA256" ]; then
    chmod 755 "$INSTALL_PATH"
    printf '%s\n' "foxguard already verified at ${INSTALL_PATH}" >&2
    exit 0
  fi
  printf '%s\n' "foxguard at ${INSTALL_PATH} has mismatched checksum; re-downloading..." >&2
fi

mkdir -p "$INSTALL_DIR"
tmpdir="$(mktemp -d "${INSTALL_DIR}/.foxguard-install.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

downloaded="${tmpdir}/${ASSET}"
printf '%s\n' "Downloading ${ASSET} from ${FOXGUARD_TAG}..." >&2
curl --fail --location --silent --show-error --retry 3 --retry-delay 2 \
  "$DOWNLOAD_URL" -o "$downloaded"

actual="$(sha256_file "$downloaded")"
if [ "$actual" != "$EXPECTED_SHA256" ]; then
  fail "checksum mismatch for ${ASSET} (expected ${EXPECTED_SHA256}, got ${actual})"
fi

chmod 755 "$downloaded"
mv -f "$downloaded" "$INSTALL_PATH"

printf '%s\n' "Installed foxguard ${FOXGUARD_TAG} (${ASSET}) to ${INSTALL_PATH}" >&2