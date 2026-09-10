#!/usr/bin/env sh
# Install the latest verified standalone 0sec binary for this host.
set -eu

REPO="0sec-labs/0sec"
RELEASE_BASE_URL="${RELEASE_BASE_URL:-https://github.com/${REPO}/releases/latest/download}"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.0sec/bin}"

fail() {
  printf '%s\n' "0sec installer: $*" >&2
  exit 1
}

case "$(uname -s)" in
  Darwin)
    case "$(uname -m)" in
      arm64) ASSET="0sec-darwin-arm64" ;;
      *) fail "unsupported macOS architecture; download a matching release asset manually" ;;
    esac
    ;;
  Linux)
    case "$(uname -m)" in
      x86_64|amd64) ASSET="0sec-linux-x64" ;;
      aarch64|arm64) ASSET="0sec-linux-arm64" ;;
      *) fail "unsupported Linux architecture; download a matching release asset manually" ;;
    esac
    ;;
  *)
    fail "unsupported operating system; download the matching GitHub Release asset manually"
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

mkdir -p "$INSTALL_DIR"
manifest="$(mktemp "${TMPDIR:-/tmp}/0sec-checksums.XXXXXX")"
binary="$(mktemp "${INSTALL_DIR}/.${ASSET}.XXXXXX")"
fg_binary=""
cleanup() {
  rm -f "$manifest" "$binary" "$fg_binary"
}
trap cleanup EXIT HUP INT TERM

printf '%s\n' "Downloading ${ASSET}…" >&2
curl --fail --location --silent --show-error --retry 3 --retry-delay 1 \
  "${RELEASE_BASE_URL}/checksums.txt" -o "$manifest"
curl --fail --location --silent --show-error --retry 3 --retry-delay 1 \
  "${RELEASE_BASE_URL}/${ASSET}" -o "$binary"

expected="$(awk -v asset="$ASSET" '$2 == asset || $2 == ("*" asset) { print $1; exit }' "$manifest")"
[ -n "$expected" ] || fail "checksums.txt has no entry for ${ASSET}"
actual="$(sha256_file "$binary")"
[ "$expected" = "$actual" ] || fail "checksum mismatch for ${ASSET}; refusing to install"

chmod 755 "$binary"
mv -f "$binary" "${INSTALL_DIR}/0sec"
binary=""
alias_path="${INSTALL_DIR}/0"
if [ -L "$alias_path" ]; then
  [ "$(readlink "$alias_path")" = "0sec" ] || fail "refusing to replace existing alias at ${alias_path}"
  rm -f "$alias_path"
elif [ -e "$alias_path" ]; then
  fail "refusing to replace existing file at ${alias_path}"
fi
ln -s "0sec" "$alias_path"
printf '%s\n' "Installed verified 0sec to ${INSTALL_DIR}/0sec (also available as ${INSTALL_DIR}/0)" >&2

# Provision the default static analyzer too, so standalone source reviews do
# not require Node/npm. INSTALL_FOXGUARD=0 opts out for pre-provisioned hosts.
if [ "${INSTALL_FOXGUARD:-1}" != "0" ]; then
  FOXGUARD_TAG="${FOXGUARD_TAG:-v0.12.0}"
  [ "$FOXGUARD_TAG" = "v0.12.0" ] || fail "update the pinned FoxGuard checksums before selecting another release"
  FOXGUARD_REPO="0sec-labs/foxguard"

  case "$(uname -s)" in
    Darwin)
      case "$(uname -m)" in
        arm64) FG_ASSET="foxguard-macos-aarch64"; FG_SHA256="3bd54b666ec399b3c9e77dbe1b1389da240807b62383f652697626cc45da2a17" ;;
        *) fail "unsupported macOS architecture for FoxGuard companion" ;;
      esac ;;
    Linux)
      case "$(uname -m)" in
        x86_64|amd64) FG_ASSET="foxguard-linux-x86_64"; FG_SHA256="0f82260e1cf944b1b5e318206777bb6df5a3accdd390421d704f5646cfc91374" ;;
        aarch64|arm64) FG_ASSET="foxguard-linux-aarch64"; FG_SHA256="26c65e4458a2540d2328975c70a5feabfa9af92ce897f1d3ec810bef16872a8e" ;;
        *) fail "unsupported Linux architecture for FoxGuard companion" ;;
      esac ;;
    *) fail "unsupported operating system for FoxGuard companion" ;;
  esac

  fg_binary="$(mktemp "${INSTALL_DIR}/.${FG_ASSET}.XXXXXX")"

  printf '%s\n' "Downloading FoxGuard ${FOXGUARD_TAG} companion (${FG_ASSET})…" >&2
  curl --fail --location --silent --show-error --retry 3 --retry-delay 2 \
    "https://github.com/${FOXGUARD_REPO}/releases/download/${FOXGUARD_TAG}/${FG_ASSET}" -o "$fg_binary"

  actual="$(sha256_file "$fg_binary")"
  [ "$FG_SHA256" = "$actual" ] || fail "FoxGuard checksum mismatch for ${FG_ASSET}; refusing to install"

  chmod 755 "$fg_binary"
  mv -f "$fg_binary" "${INSTALL_DIR}/foxguard"
  printf '%s\n' "Installed verified FoxGuard to ${INSTALL_DIR}/foxguard" >&2
fi

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *) printf '%s\n' "Add ${INSTALL_DIR} to PATH to run: 0sec --help (or 0 --help)" >&2 ;;
esac
