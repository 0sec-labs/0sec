#!/usr/bin/env bash
# Build KASAN-enabled kernel + rootfs for 0sec kernel crash validator
#
# Usage: ./build.sh [output-dir]
#
# Outputs:
#   bzImage       — KASAN-enabled kernel
#   rootfs.img    — Debian root filesystem with GCC/binutils + shared-workdir boot path
#   kernel.config — kernel .config
#
# After building, configure the kernel VM runner for one invocation:
#   env 0SEC_KERNEL_QEMU=1 \
#     0SEC_KERNEL_QEMU_KERNEL=/path/to/bzImage \
#     0SEC_KERNEL_QEMU_DISK=/path/to/rootfs.img \
#     0sec ingest --verify <crash-reports-dir>
#
# NOTE: We use `docker buildx build` (not classic `docker build`) because the
# Dockerfile pins individual stages with `FROM --platform=linux/amd64`. The
# legacy builder silently ignores per-stage platform directives on arm64
# hosts, which produces an arm64 rootfs that cannot boot the x86_64 kernel.
# buildx honors per-stage platform pins, so the rootfs ends up x86_64 as
# intended regardless of host arch.

set -euo pipefail

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is required" >&2; exit 1; }
docker buildx version >/dev/null 2>&1 || {
  echo "ERROR: docker buildx required. Install via brew install docker-buildx (macOS) or apt-get install docker-buildx-plugin (linux)" >&2
  exit 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-${SCRIPT_DIR}/out}"
KERNEL_MAKE_JOBS="$(printenv 0SEC_KERNEL_VM_MAKE_JOBS 2>/dev/null || true)"
: "${KERNEL_MAKE_JOBS:=4}"

mkdir -p "${OUT_DIR}"

echo "Building 0sec kernel VM image..."
echo "  Dockerfile: ${SCRIPT_DIR}/Dockerfile"
echo "  Output dir: ${OUT_DIR}"
echo ""
echo "This will take 15-30 minutes (kernel compilation)."
echo ""

docker buildx build \
  --load \
  --platform linux/amd64 \
  --build-arg "KERNEL_MAKE_JOBS=${KERNEL_MAKE_JOBS}" \
  -t 0sec-kernel-builder \
  -f "${SCRIPT_DIR}/Dockerfile" \
  "${SCRIPT_DIR}"

docker run --rm \
  --privileged \
  -e HOST_UID="$(id -u)" \
  -e HOST_GID="$(id -g)" \
  -v "${OUT_DIR}:/out" \
  0sec-kernel-builder

echo ""
echo "Done. Kernel VM artifacts:"
ls -lh "${OUT_DIR}"/bzImage "${OUT_DIR}"/rootfs.img "${OUT_DIR}"/kernel.config "${OUT_DIR}"/osec_vm_key "${OUT_DIR}"/osec_vm_key.pub 2>/dev/null

echo ""
echo "To use with 0sec:"
echo "  env 0SEC_KERNEL_QEMU=1 0SEC_KERNEL_QEMU_KERNEL=${OUT_DIR}/bzImage \\"
echo "    0SEC_KERNEL_QEMU_DISK=${OUT_DIR}/rootfs.img \\"
echo "    0sec ingest --verify <crash-reports-dir>"
