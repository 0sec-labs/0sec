#!/usr/bin/env sh
# Provision the pinned FoxGuard binary for this host architecture.
#
# Downloads the verified release asset from 0sec-labs/foxguard to a configurable
# install directory (default: /usr/local/bin). The pinned version is the same
# FOXGUARD_PINNED_TAG used by the 0sec runtime (v0.12.0).
#
# Usage:
#   bash scripts/provision-foxguard.sh                    # install to /usr/local/bin
#   INSTALL_DIR=/opt/bin bash scripts/provision-foxguard.sh
set -eu

FOXGUARD_REPO="0sec-labs/foxguard"
FOXGUARD_TAG="${FOXGUARD_TAG:-v0.12.0}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# ── v0.12.0 checksums (cross-checked against the release's checksums.txt) ──
# Update the pin and its checksums together when upgrading.
FOXGUARD_SHA256_LINUX_X64="0f82260e1cf944b1b5e318206777bb6df5a3accdd390421d704f5646cfc91374"
FOXGUARD_SHA256_LINUX_ARM64="26c65e4458a2540d2328975c70a5feabfa9af92ce897f1d3ec810bef16872a8e"
FOXGUARD_SHA256_MACOS_ARM64="3bd54b666ec399b3c9e77dbe1b1389da240807b62383f652697626cc45da2a17"
FOXGUARD_SHA256_MACOS_X64="ccf9a66fbbef7d9b801f9d9f6083bbf2869f9643f6312f10454256cfe22bd2b1"
FOXGUARD_SHA256_WIN_X64="5ae0907a894bd4cf02426a581674083742963ff687ea67d872fd44fe0405deaa"

fail() {
  printf '%s\n' "foxguard provisioner: $*" >&2
  exit 1
}

[ "$FOXGUARD_TAG" = "v0.12.0" ] || fail "update the pinned checksums before selecting another release"

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