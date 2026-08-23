---
title: Kernel VM Verification
description: Build and configure the QEMU guest used by 0sec ingest --verify.
---

`0sec ingest --verify` runs C reproducers inside a local QEMU guest and compares
the guest `dmesg` against the imported kernel crash report. Without the VM,
kernel verification stays static-only — 0sec won't claim a crash was reproduced.

## What the repo provides

A maintained build recipe at `packages/core/src/triage/kernel-vm/` builds:

- `bzImage` — Linux 6.8.12 for x86_64 with KASAN, UBSAN, KCSAN, lock debugging,
  RCU stall detection, and virtio/9p/ext4/NFS/Bluetooth/WiFi/SCTP support.
- `rootfs.img` — 512 MB Debian Bookworm ext4 with `gcc`, `binutils`, `make`,
  `procps`, `kmod`, `strace`, `gdb`, OpenSSH, and `/sbin/0sec-init`.
- `kernel.config` — the exact config used for the build.
- `osec_vm_key[.pub]` — root SSH keypair for manual debugging only (the verifier
  uses a QEMU 9p share, not SSH).

Prebuilt artifacts are not committed. Build locally or let the GitHub Actions
E2E workflow build and cache them.

## Requirements

- Docker (reproducible guest build)
- QEMU (`qemu-system-x86_64`)
- ~20 GB free disk for the build cache
- Enough guest memory (default 2048 MB)
- Optional KVM acceleration on Linux; macOS/CI run without it, but may need
  higher boot/reproducer timeouts.

## Build recipe

From the repo root:

```bash
pnpm install --frozen-lockfile

cd packages/core/src/triage/kernel-vm
0SEC_KERNEL_VM_MAKE_JOBS=4 ./build.sh "$HOME/.0sec/kernel-vm/linux-6.8.12-kasan"
```

Output:

```text
$HOME/.0sec/kernel-vm/linux-6.8.12-kasan/
  bzImage
  rootfs.img
  kernel.config
  osec_vm_key
  osec_vm_key.pub
```

Treat the output directory as a local cache; regenerate it when the Dockerfile,
kernel version, or guest package list changes.

## Configure 0sec

Required:

```bash
export 0SEC_KERNEL_QEMU=1
export 0SEC_KERNEL_QEMU_KERNEL="$HOME/.0sec/kernel-vm/linux-6.8.12-kasan/bzImage"
export 0SEC_KERNEL_QEMU_DISK="$HOME/.0sec/kernel-vm/linux-6.8.12-kasan/rootfs.img"
```

Recommended local defaults:

```bash
export 0SEC_KERNEL_QEMU_MEMORY_MB=2048
export 0SEC_KERNEL_QEMU_SMP=2
export 0SEC_KERNEL_QEMU_BOOT_TIMEOUT_SEC=180
export 0SEC_KERNEL_QEMU_TIMEOUT_SEC=60
export 0SEC_KERNEL_QEMU_ARTIFACT_DIR="$HOME/.0sec/kernel-vm/runs"
```

On Linux hosts with KVM: `export 0SEC_KERNEL_QEMU_ACCEL=kvm`.

Leave `0SEC_KERNEL_QEMU_APPEND` unset unless using a custom guest. Default:

```text
console=ttyS0 root=/dev/vda rw nokaslr panic=-1 init=/sbin/0sec-init
```

## Run verification

Place crash reports and reproducers in one directory; file stems are matched:

```text
crashes/
  bug-001.log
  bug-001.c
  bug-002.report
  bug-002.syz
```

```bash
0sec ingest ./crashes --verify --output json
```

For each C reproducer 0sec writes `repro.c` and `runner.sh` to a temp dir, boots
QEMU with a 9p share (`osecshare`), lets `/sbin/0sec-init` run
`/mnt/0sec/runner.sh`, compiles and runs the reproducer under the timeout, and
copies `compile.log`, `run.log`, `dmesg.log`, markers, and the serial log back
to the artifact directory (when configured).

### Privilege and provenance

The guest runs reproducers as UID 0 by default, so it can prove repeatable crash
behavior but not unprivileged reachability — such evidence is marked privileged.
Zero-cap certification uses a trusted launcher that drops all IDs, groups, and
capabilities, sets `no_new_privs`, and binds a hashed receipt to a nonce and the
reproducer digest; missing or inconsistent evidence falls back to privileged.

Schema-v2 receipts also bind a staged copy of the `bzImage`, its config SHA-256,
and the expected kernel release; QEMU boots the staged image and the host
re-hashes it before and after. The guest supplies its runtime release
(`/proc/sys/kernel/osrelease`) and boot UUID; a release mismatch, malformed or
repeated UUID, or staged-image change invalidates the gate. This catches
ordinary label/artifact mixups but is **not** hardware attestation (no TPM /
SEV-SNP) and does not defend against a malicious host or guest kernel, nor prove
the running kernel config without a runtime measurement like `/proc/config.gz`.

If `0SEC_KERNEL_QEMU_ARTIFACT_DIR` is unset, the temp run directory is deleted
after each attempt.

## Guest contract

A custom guest must satisfy:

| Requirement | Contract |
| --- | --- |
| Architecture | x86_64, bootable by `qemu-system-x86_64` |
| Root device | `root=/dev/vda` (or matching custom append) |
| Init path | `/sbin/0sec-init` (unless `0SEC_KERNEL_QEMU_APPEND` changed) |
| Host share | Mount 9p tag `osecshare` at `/mnt/0sec` |
| Runner | Execute `/mnt/0sec/runner.sh`, leave results in the share |
| Compiler | `/usr/bin/gcc` plus libc headers and `binutils` |
| Logs | `dmesg` readable after the reproducer runs |
| Kernel | Debug-friendly, crash signal visible in `dmesg` |

SSH is not part of the contract; the keypair is only for manual debugging.

## Environment variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `0SEC_KERNEL_QEMU` | Yes | - | `1` to enable VM execution |
| `0SEC_KERNEL_QEMU_KERNEL` | Yes | - | Path to `bzImage` |
| `0SEC_KERNEL_QEMU_DISK` | Yes | - | Path to `rootfs.img` or other bootable disk |
| `0SEC_KERNEL_QEMU_CONFIG` | For provenance | - | Config used to build the selected kernel |
| `0SEC_KERNEL_QEMU_EXPECTED_RELEASE` | For prebuilt artifacts | - | Exact expected `uname -r`; never inferred from filename |
| `0SEC_KERNEL_QEMU_BINARY` | No | `qemu-system-x86_64` | QEMU binary |
| `0SEC_KERNEL_QEMU_DISK_FORMAT` | No | inferred | `raw` or `qcow2` |
| `0SEC_KERNEL_QEMU_MEMORY_MB` | No | `2048` | Guest memory (MB) |
| `0SEC_KERNEL_QEMU_SMP` | No | `2` | Guest CPU count |
| `0SEC_KERNEL_QEMU_APPEND` | No | see above | Kernel command line |
| `0SEC_KERNEL_QEMU_ACCEL` | No | - | Accelerator, e.g. `kvm` |
| `0SEC_KERNEL_QEMU_INITRD` | No | - | Optional initrd for custom guests |
| `0SEC_KERNEL_QEMU_BOOT_TIMEOUT_SEC` | No | `120` | Boot + setup time |
| `0SEC_KERNEL_QEMU_TIMEOUT_SEC` | No | `60` | Reproducer time |
| `0SEC_KERNEL_QEMU_SHARE_TAG` | No | `osecshare` | 9p mount tag |
| `0SEC_KERNEL_QEMU_ARTIFACT_DIR` | No | - | Where per-run artifacts are preserved |

## Troubleshooting

If the VM exits early, inspect `serial.log` in `0SEC_KERNEL_QEMU_ARTIFACT_DIR`.
Common causes:

- The guest didn't mount the 9p share (keep `0SEC_KERNEL_QEMU_SHARE_TAG` and
  `/sbin/0sec-init` in sync).
- Missing `gcc` or libc headers in a custom guest.
- `dmesg` unreadable, or boot timeout too low without KVM.
- Custom append line no longer points at the correct root disk or init.

`.github/workflows/kernel-validator-e2e.yml` is the smoke-tested CI reference: it
builds the artifacts, boots QEMU, runs a real `ingest --verify`, and uploads the
logs.

## Batch validation

Maintainers can run `.github/workflows/kernel-validator-batch.yml` manually to
validate a curated syzbot corpus against the real VM. The default corpus is
`scripts/kernel-validator-batch-corpus.json`; a JSON override is accepted. It
uploads `summary.json` (with `verified`, `reproduced`, `crashMatch`,
`reproducedMismatch`, `staticOnly`, `failed`, `errored` counts), `summary.md`,
per-case `result.json`, raw CLI output, and VM artifacts. It is
`workflow_dispatch` only.
