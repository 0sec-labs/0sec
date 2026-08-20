#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# Long-running exact-LTS pilots use custom syzkaller builds. Refuse telemetry
# if any manager-side or guest-side runtime binary changed after promotion.
sha256sum --quiet -c /root/syz/lifetime-exact94-pinned.sha256
sha256sum --quiet -c /root/syz/aio-exact94-pinned.sha256

exec flock --nonblock /run/zeroverse-manager-progress.lock \
  "$script_dir/audit-manager-progress.py" \
  --state /root/syz/manager-progress.json \
  keyrings=http://127.0.0.1:56750/metrics \
  futexpi=http://127.0.0.1:56747/metrics \
  pipe=http://127.0.0.1:56749/metrics \
  unix=http://127.0.0.1:56743/metrics \
  vsock=http://127.0.0.1:56746/metrics \
  afalg=http://127.0.0.1:56741/metrics \
  tls=http://127.0.0.1:56742/metrics \
  kcsan-kcm=http://127.0.0.1:56772/metrics \
  kcsan-aio=http://127.0.0.1:56771/metrics \
  kcsan-unix=http://127.0.0.1:56790/metrics \
  lifetime-exact94=http://127.0.0.1:56751/metrics \
  aio-exact94=http://127.0.0.1:56761/metrics
