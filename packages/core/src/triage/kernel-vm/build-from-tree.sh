#!/usr/bin/env bash
# Build pwnkit kernel VM artifacts from a local Linux source tree.
#
# Usage:
#   build-from-tree.sh <kernel-tree> <out-dir> [kasan]

set -euo pipefail

KERNEL_TREE="${1:?kernel tree required}"
OUT_DIR="${2:?output directory required}"
CONFIG_PROFILE="${3:-kasan}"

if [[ "${CONFIG_PROFILE}" != "kasan" ]]; then
  echo "unsupported kernel config profile: ${CONFIG_PROFILE}" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "${OUT_DIR}"

docker build \
  --build-arg "KERNEL_MAKE_JOBS=${PWNKIT_KERNEL_VM_MAKE_JOBS:-4}" \
  -t pwnkit-kernel-builder-local \
  -f "${SCRIPT_DIR}/Dockerfile.local-tree" \
  "${SCRIPT_DIR}"

docker run --rm \
  --privileged \
  -e HOST_UID="$(id -u)" \
  -e HOST_GID="$(id -g)" \
  -v "${KERNEL_TREE}:/src/linux:ro" \
  -v "${OUT_DIR}:/out" \
  pwnkit-kernel-builder-local
