#!/usr/bin/env bash
# Build 0sec kernel VM artifacts from a local Linux source tree.
#
# Usage:
#   build-from-tree.sh <kernel-tree> <out-dir> [kasan|kcsan]
#
# Profiles:
#   kasan  (default) — KASAN/UBSAN memory-error sanitizer build.
#   kcsan            — Kernel Concurrency Sanitizer + full preemption: the race
#                      lane KASAN is blind to. The per-profile sanitizer flags
#                      are branched inside Dockerfile.local-tree on $CONFIG_PROFILE
#                      and mirror buildFlagsForProfile() in kernel-vm-runner.ts
#                      (keep the two in sync).

set -euo pipefail

KERNEL_TREE="${1:?kernel tree required}"
OUT_DIR="${2:?output directory required}"
CONFIG_PROFILE="${3:-kasan}"

if [[ "${CONFIG_PROFILE}" != "kasan" && "${CONFIG_PROFILE}" != "kcsan" ]]; then
  echo "unsupported kernel config profile: ${CONFIG_PROFILE} (known: kasan, kcsan)" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "${OUT_DIR}"
KERNEL_MAKE_JOBS="$(printenv 0SEC_KERNEL_VM_MAKE_JOBS 2>/dev/null || true)"
: "${KERNEL_MAKE_JOBS:=4}"

docker build \
  --build-arg "KERNEL_MAKE_JOBS=${KERNEL_MAKE_JOBS}" \
  -t 0sec-kernel-builder-local \
  -f "${SCRIPT_DIR}/Dockerfile.local-tree" \
  "${SCRIPT_DIR}"

docker run --rm \
  --privileged \
  -e HOST_UID="$(id -u)" \
  -e HOST_GID="$(id -g)" \
  -e CONFIG_PROFILE="${CONFIG_PROFILE}" \
  -v "${KERNEL_TREE}:/src/linux:ro" \
  -v "${OUT_DIR}:/out" \
  0sec-kernel-builder-local
