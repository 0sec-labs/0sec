#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
workdirs=(
  /root/syz/wd-keyrings
  /root/syz/wd-futexpi
  /root/syz/wd-sched
  /root/syz/wd-pipe
  /root/syz/wd-unix
  /root/syz/wd-vsock
  /root/syz/wd-afalg
  /root/syz/wd-tls
  /root/syz/wd-drivers
  /root/syz/wd-kcsan-afalg-setuid
  /root/syz/wd-kcsan-kcm
  /root/syz/wd-kcsan-aio
  /root/syz/wd-kcsan-unix
  /root/syz/wd-lifetime-exact94
  /root/syz/wd-aio-exact94
)

"$script_dir/audit-new-crash-buckets.py" \
  --state /root/syz/crash-bucket-monitor.json \
  --evidence-dir /root/syz/evidence-inbox \
  "${workdirs[@]}"

exec "$script_dir/audit-focused-bucket-ledger.py" \
  --ledger "$script_dir/focused-bucket-ledger.json" \
  "${workdirs[@]}"
