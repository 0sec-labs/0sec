---
title: Kernel VM Verification
description: Build and configure the QEMU guest used by 0sec ingest --verify.
---

`0sec ingest --verify` can run C reproducers inside a local QEMU guest and compare
the guest `dmesg` output with the imported kernel crash report. Without this VM,
kernel verification remains static-only and 0sec will not claim that a crash was
reproduced.

## What The Repo Provides

0sec ships a maintained build recipe at
`packages/core/src/triage/kernel-vm/`. The recipe builds:

- `bzImage`: Linux 6.8.12 for x86_64 with KASAN, UBSAN, KCSAN, lock debugging,
  RCU stall detection, virtio, 9p, ext4, NFS/NFSd, Bluetooth, WiFi, and SCTP
  support enabled.
- `rootfs.img`: a 512 MB Debian Bookworm ext4 image with `gcc`, `binutils`,
  `make`, `procps`, `kmod`, `strace`, `gdb`, OpenSSH, and `/sbin/0sec-init`.
- `kernel.config`: the exact kernel config used for the build.
- `osec_vm_key` and `osec_vm_key.pub`: a root SSH keypair for manual guest
  debugging. The current 0sec verifier does not use SSH; it communicates
  through a QEMU 9p shared directory.

The repository does not commit prebuilt VM artifacts. Build them locally or let
the GitHub Actions E2E workflow build and cache them.

## Requirements

Install these host tools before building or running VM-backed verification:

- Docker for the reproducible guest build.
- QEMU, usually `qemu-system-x86_64`, for local verification runs.
- At least 20 GB of free disk space for the Docker build cache and kernel build.
- Enough memory for the guest. The runner defaults to 2048 MB.
- Optional KVM acceleration on Linux. macOS and CI can run without acceleration,
  but boot and reproducer timeouts may need to be higher.

## Known-Good Build Recipe

From the repository root:

```bash
pnpm install --frozen-lockfile

cd packages/core/src/triage/kernel-vm
0SEC_KERNEL_VM_MAKE_JOBS=4 ./build.sh "$HOME/.0sec/kernel-vm/linux-6.8.12-kasan"
```

Expected output directory:

```text
$HOME/.0sec/kernel-vm/linux-6.8.12-kasan/
  bzImage
  rootfs.img
  kernel.config
  osec_vm_key
  osec_vm_key.pub
```

The Dockerfile pins the kernel source to `linux-6.8.12` from `cdn.kernel.org`
and builds an amd64 Debian Bookworm guest. Treat the output directory as a local
cache: regenerate it when the Dockerfile, kernel version, or guest package list
changes.

## Configure 0sec

Set the required environment variables:

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

On Linux hosts with KVM:

```bash
export 0SEC_KERNEL_QEMU_ACCEL=kvm
```

Leave `0SEC_KERNEL_QEMU_APPEND` unset unless you use a custom guest. The default
is:

```text
console=ttyS0 root=/dev/vda rw nokaslr panic=-1 init=/sbin/0sec-init
```

## Run Verification

Place syzbot-style crash reports and reproducers in the same directory. File
stems are matched:

```text
crashes/
  bug-001.log
  bug-001.c
  bug-002.report
  bug-002.syz
```

Run:

```bash
0sec ingest ./crashes --verify --output json
```

For each C reproducer, 0sec:

1. Creates a temporary host directory.
2. Writes `repro.c` and `runner.sh` into that directory.
3. Boots QEMU with `bzImage`, `rootfs.img`, and a 9p share mounted as
   `osecshare`.
4. Lets `/sbin/0sec-init` mount the share and execute `/mnt/0sec/runner.sh`.
5. Compiles the reproducer with guest `gcc`.
6. Runs the reproducer under the configured timeout.
7. Copies `compile.log`, `run.log`, `dmesg.log`, marker files, and the serial log
   back to the host artifact directory when configured.

The current guest init executes both C and syzkaller reproducers as UID 0. This
oracle can establish repeatable crash behavior, but it cannot establish
unprivileged or zero-cap reachability. Research evidence from this runner is
therefore marked privileged with a runner-contract basis.

An explicit unprivileged execution identity uses a trusted guest launcher before
the reproducer starts. The launcher drops all supplementary groups and real,
effective, and saved IDs; requires zero inheritable, permitted, effective, and
ambient capabilities; sets `no_new_privs`; disables creation of additional user
namespaces; and binds the receipt to a nonce and the reproducer digest. Every
counted N-of-K hit must carry an independently hashed receipt in the aggregate
manifest. Missing or inconsistent evidence falls back to privileged.

Schema-v2 receipts also bind a private staged copy of the host-selected
`bzImage`, the SHA-256 of its associated build config, and the exact expected
kernel release. QEMU boots the staged image rather than the mutable cache path;
the host hashes the staged image and config before and after the run. The config
digest identifies the build artifact supplied by the trusted orchestrator; it
does not prove the running kernel configuration unless separately matched to a
runtime measurement such as `/proc/config.gz`. The launcher reads the
running release from `/proc/sys/kernel/osrelease` and the boot UUID from
`/proc/sys/kernel/random/boot_id`; a release mismatch, malformed UUID, repeated
boot UUID, or staged image/config change invalidates the gate. Each per-boot
dmesg digest is included in the JSON aggregate manifest. These checks catch
ordinary label and artifact mixups, including the observed 6.12.95-versus-
6.12.93 mismatch. They do not distinguish two different images that honestly
report the same release without a guest- or hardware-backed image measurement.

The direct-VM contract also requires the launcher to share the trusted guest
PID namespace with PID 1. Before dropping credentials, it opens PID 1's user
namespace and later compares that namespace object with the reproducer's own
user namespace. A missing or different reference fails zero-cap certification
closed. Deployments that wrap the launcher in another PID namespace must pass
an initial-user-namespace reference from trusted guest init instead.

This receipt trusts the host orchestrator, QEMU command, VM kernel, guest init,
and launcher. The staged-image/config hashes are host-side launch bindings, not values
independently measured by the guest; the guest independently supplies only its
runtime release and boot UUID. This protects against ordinary artifact mixups
and reproducer-controlled privilege changes, but is not TPM, SEV-SNP, or other
hardware remote attestation against a malicious host or guest kernel.

The programmatic `KernelVerifier` dependency-injection hook is a trusted testing
and integration boundary. The adapter still re-reads its evidence graph before
zero-cap promotion, but it does not authenticate a hostile verifier process.
Nonces and boot UUIDs prove uniqueness within one N-of-K graph, not global
freshness: a complete, internally valid graph can be replayed under this trust
model. Preventing cross-run replay requires a separately authenticated run ID,
timestamp policy, or hardware-backed challenge.

If `0SEC_KERNEL_QEMU_ARTIFACT_DIR` is unset, 0sec deletes the temporary run
directory after each verification attempt.

## Guest Contract

A custom guest must satisfy this contract:

| Requirement | Contract |
| --- | --- |
| Architecture | x86_64 guest bootable by `qemu-system-x86_64` |
| Root device | `root=/dev/vda` by default, or matching custom append line |
| Init path | `/sbin/0sec-init`, unless `0SEC_KERNEL_QEMU_APPEND` is changed |
| Host share | Mount QEMU 9p tag `osecshare` at `/mnt/0sec` |
| Runner | Execute `/mnt/0sec/runner.sh` and leave results in the same share |
| Compiler | `/usr/bin/gcc` plus libc headers and `binutils` |
| Logs | `dmesg` readable after the reproducer runs |
| Kernel | Debug-friendly kernel with crash signal visible in `dmesg` |

SSH is not part of the verifier contract. The generated keypair is exported only
for manual debugging if you boot the image yourself with a network device and
port forwarding.

## Environment Variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `0SEC_KERNEL_QEMU` | Yes | - | Set to `1` to enable VM execution. |
| `0SEC_KERNEL_QEMU_KERNEL` | Yes | - | Path to `bzImage`. |
| `0SEC_KERNEL_QEMU_DISK` | Yes | - | Path to `rootfs.img` or another bootable disk. |
| `0SEC_KERNEL_QEMU_CONFIG` | Yes for provenance | - | Path to the exact config used to build the selected kernel. |
| `0SEC_KERNEL_QEMU_EXPECTED_RELEASE` | Yes for prebuilt/env artifacts | - | Exact expected `uname -r`; never inferred from the image filename. |
| `0SEC_KERNEL_QEMU_BINARY` | No | `qemu-system-x86_64` | QEMU binary to execute. |
| `0SEC_KERNEL_QEMU_DISK_FORMAT` | No | inferred | `raw` or `qcow2`; inferred from extension when unset. |
| `0SEC_KERNEL_QEMU_MEMORY_MB` | No | `2048` | Guest memory in MB. |
| `0SEC_KERNEL_QEMU_SMP` | No | `2` | Guest CPU count. |
| `0SEC_KERNEL_QEMU_APPEND` | No | see above | Kernel command line. |
| `0SEC_KERNEL_QEMU_ACCEL` | No | - | QEMU accelerator, for example `kvm`. |
| `0SEC_KERNEL_QEMU_INITRD` | No | - | Optional initrd path for custom guests. |
| `0SEC_KERNEL_QEMU_BOOT_TIMEOUT_SEC` | No | `120` | Time allowed for boot and guest setup. |
| `0SEC_KERNEL_QEMU_TIMEOUT_SEC` | No | `60` | Time allowed for the reproducer. |
| `0SEC_KERNEL_QEMU_SHARE_TAG` | No | `osecshare` | 9p mount tag expected by the guest init. |
| `0SEC_KERNEL_QEMU_ARTIFACT_DIR` | No | - | Host directory where per-run artifacts are preserved. |

## Troubleshooting

If the VM exits before producing results, inspect `serial.log` in
`0SEC_KERNEL_QEMU_ARTIFACT_DIR`. Common causes:

- The guest did not mount the 9p share. Keep `0SEC_KERNEL_QEMU_SHARE_TAG` and
  `/sbin/0sec-init` in sync.
- `gcc` or libc headers are missing in a custom guest.
- The guest cannot read `dmesg`.
- The boot timeout is too low on hosts without KVM.
- A custom kernel append line no longer points at the correct root disk or init.

The repository E2E workflow, `.github/workflows/kernel-validator-e2e.yml`, is the
smoke-tested reference for CI. It builds the same artifacts, boots QEMU, runs a
real `ingest --verify` flow, and uploads the VM logs plus runner outputs as
artifacts.

## Batch Validation Workflow

Maintainers can run `.github/workflows/kernel-validator-batch.yml` manually from
GitHub Actions to validate a curated syzbot corpus against the real VM runner.
The default corpus lives at `scripts/kernel-validator-batch-corpus.json`; the
workflow also accepts a JSON override for one-off corpus experiments.

The workflow uploads `summary.json`, `summary.md`, each case's `result.json`,
raw CLI output, and per-case VM artifacts. `summary.json` separates
VM-reproduced verdicts from static-only verdicts with these top-level counts:
`verified`, `reproduced`, `crashMatch`, `reproducedMismatch`, `staticOnly`,
`failed`, and `errored`.

The batch workflow is `workflow_dispatch` only. Add a schedule only after the
curated corpus and VM artifact cache are stable enough for unattended runs.
