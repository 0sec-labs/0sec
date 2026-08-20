#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
audit="$script_dir/audit-syzkaller-lane.py"

run() {
  local lane=$1
  shift
  echo "== $lane =="
  "$audit" "/root/syz/$lane.cfg" "$@"
}

run keyrings \
  add_key \
  'keyctl$KEYCTL_PKEY_ENCRYPT' \
  'ioctl$IOC_WATCH_QUEUE_SET_FILTER'
run futexpi futex futex_waitv
run pipe pipe2 splice tee vmsplice
run unix 'socket$unix' 'sendmsg$unix' 'recvmsg$unix'
run vsock \
  --exec-only 'socket$vsock_stream' \
  'socket$vsock_stream' \
  'connect$vsock_stream' \
  'accept4$vsock_stream'
run afalg \
  --exec-only 'socket$alg' \
  'socket$alg' \
  'bind$alg' \
  'sendmsg$alg' \
  'read$alg'
run tls \
  'setsockopt$inet_tcp_TLS_TX' \
  'setsockopt$inet_tcp_TLS_RX' \
  'setsockopt$inet6_tcp_TLS_TX' \
  'setsockopt$inet6_tcp_TLS_RX'
run kcsan-kcm \
  'socket$kcm' \
  'ioctl$sock_kcm_SIOCKCMCLONE' \
  'ioctl$sock_kcm_SIOCKCMATTACH' \
  'ioctl$sock_kcm_SIOCKCMUNATTACH' \
  'sendmsg$kcm' \
  'recvmsg$kcm'
run lifetime-exact94 \
  'syz_clone$lifetime_child' \
  syz_pidfd_open \
  pidfd_send_signal \
  pidfd_getfd \
  futex \
  futex_waitv \
  set_robust_list \
  semtimedop \
  msgsnd \
  msgrcv \
  shmat \
  shmdt
run aio-exact94 \
  io_setup \
  io_submit \
  io_getevents \
  io_pgetevents \
  io_cancel \
  io_destroy
