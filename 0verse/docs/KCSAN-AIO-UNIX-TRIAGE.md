# KCSAN AIO and AF_UNIX evidence gate

The `wd-kcsan-aio` and `wd-kcsan-unix` managers are active discovery lanes,
not adjudicators. Their crash directories are monitored by
`audit-live-crash-buckets.sh`, their execution and coverage counters are
sampled from ports `56771` and `56790`, and every observed bucket must have an
explicit entry in `focused-bucket-ledger.json`.

The read-only 2026-07-18 snapshot contains 91 AIO buckets and 51 AF_UNIX
buckets, with 36 shared hashes and 106 unique hashes. No report contained a
paired AIO `kioctx` lifetime access. The AF_UNIX-specific
`fasync_remove_entry / sock_wake_async` report is a known public duplicate, and
the shared `can't ssh into the instance` bucket is infrastructure. These
dispositions do not suppress their preserved evidence.

## Exact-title rule

Bucket `a21e71f73f22603b74abc8929a2c1077db9b3f37` remains a candidate. Fourteen
reports enter `unix_stream_read_generic`/`unix_stream_recvmsg`; six include
`manage_oob` and five include `unix_stream_data_wait`. The manager's automated
reproduction attempt instead emitted `KCSAN: data-race in
virtqueue_get_buf_ctx`. That is wrong-title contamination, not reproduction of
the soft lockup.

The ledger schema rejects any record that uses a `wrong-title` reproduction to
classify the original exact-title bucket as negative, quarantined,
infrastructure, or a known duplicate. Absence of a reproducer is likewise not
negative evidence.

## Isolated replay protocol

Never run replay from, or write replay artifacts into, either active manager
workdir. First preserve a selected original `logN` in a revision-addressed
evidence directory. Use a separate one-VM config and a separate workdir, then
run:

```bash
/root/syzkaller/bin/syz-repro \
  -config /root/syz/repro-unix-a21-one-vm.cfg \
  -count 1 \
  -title /root/syz/repro-unix-a21/title.txt \
  -output /root/syz/repro-unix-a21/repro.prog \
  -crepro /root/syz/repro-unix-a21/repro.c \
  /root/syz/repro-unix-a21/source/logN
```

Accept the result only if `title.txt` normalizes exactly to `BUG: soft lockup
in unix_stream_recvmsg`. A transport, timer, KCSAN, or other title leaves the
candidate unreproduced and must be recorded as `wrong-title`.

After exact-title minimization, run the same program at least 20 times on each
of: the original KCSAN build, the same kernel without KCSAN/KCOV, and a KASAN
build. Capture all-CPU stacks at 10 and 20 seconds. A candidate may be demoted
only from exact-title evidence and an explicit technical rationale; never from
the outcome of an unrelated crash encountered during minimization.
