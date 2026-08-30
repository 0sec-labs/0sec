#!/usr/bin/env bash
# Exercise every supported public installation path in a fresh container.
#
# Usage:
#   bash scripts/install-e2e.sh [binary|source|container|all]
set -euo pipefail

readonly REPOSITORY="0sec-labs/0sec"
readonly IMAGE="ghcr.io/${REPOSITORY}:latest"
readonly METHOD="${1:-all}"

require_docker() {
  command -v docker >/dev/null 2>&1 || {
    echo "docker is required to run installation E2E checks" >&2
    exit 2
  }
  docker info >/dev/null 2>&1 || {
    echo "an accessible Docker daemon is required to run installation E2E checks" >&2
    exit 2
  }
}

check_binary_install() {
  docker run --rm --pull=always ubuntu:24.04 bash -ceu '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl
    rm -rf /var/lib/apt/lists/*

    export HOME=/tmp/0sec-home
    curl -fsSL https://raw.githubusercontent.com/0sec-labs/0sec/main/install.sh | bash
    export PATH="$HOME/.0sec/bin:$PATH"
    0 --help >/dev/null
    0sec --help >/dev/null
  '
}

check_source_install() {
  docker run --rm --pull=always node:24-bookworm bash -ceu '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates git
    rm -rf /var/lib/apt/lists/*

    git clone --depth 1 https://github.com/0sec-labs/0sec.git /work/0sec
    cd /work/0sec
    corepack enable
    pnpm install --frozen-lockfile
    pnpm build
    node packages/cli/dist/index.js --help >/dev/null
  '
}

check_container_install() {
  docker run --rm --pull=always "$IMAGE" --help >/dev/null
}

require_docker
case "$METHOD" in
  binary) check_binary_install ;;
  source) check_source_install ;;
  container) check_container_install ;;
  all)
    check_binary_install
    check_source_install
    check_container_install
    ;;
  *)
    echo "usage: $0 [binary|source|container|all]" >&2
    exit 2
    ;;
esac
