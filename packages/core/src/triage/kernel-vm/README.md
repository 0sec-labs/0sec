# 0sec Kernel VM — KASAN-enabled crash reproducer

Build recipe for the KASAN-enabled Linux kernel + root filesystem used by
automated kernel crash validation.

## Quick start

```bash
# Build (15-30 min, requires Docker)
./build.sh ./out

# Configure
export 0SEC_KERNEL_QEMU=1
export 0SEC_KERNEL_QEMU_KERNEL=./out/bzImage
export 0SEC_KERNEL_QEMU_DISK=./out/rootfs.img

# Run with verification
0sec ingest --verify /path/to/crash-reports/

# Run a standalone C reproducer through the same VM oracle
0sec ingest --reproducer ./poc.c --kernel-tree ~/src/linux --config kasan --output json

# Raw .syz programs require syz-execprog in the guest image
0sec ingest --syz ./program.syz --kernel-tree ~/src/linux --config kasan --output json
```

## What's included

**Kernel** (bzImage):
- Linux 6.8.12 with KASAN (generic, inline, stack, vmalloc)
- UBSAN (bounds, shift, div-zero, bool, enum, alignment)
- KCSAN (data race detection)
- PROVE_LOCKING, DEBUG_ATOMIC_SLEEP, RCU stall detection
- Subsystem support: NFS/NFSd, bluetooth, WiFi (mac80211), SCTP, 9P, ext4
- nokaslr for reproducible crash addresses
- virtio drivers for QEMU

**Root filesystem** (rootfs.img, 512MB ext4):
- Debian Bookworm minimal
- GCC + binutils + libc-dev for reproducer compilation
- gdb, strace for debugging
- dedicated `/sbin/0sec-init` boot path that mounts the host 9p share and runs `/mnt/0sec/runner.sh`
- OpenSSH + exported `osec_vm_key` for manual debugging only. The verifier
  itself does not use SSH.

The repository does not commit prebuilt images. Build them locally with
`./build.sh`, or use `.github/workflows/kernel-validator-e2e.yml` as the CI
reference that builds and caches the same artifacts.

## Guest contract

The 0sec verifier boots QEMU with the kernel image, disk image, and a 9p host
share. A compatible guest must:

- boot as x86_64 under `qemu-system-x86_64`
- mount the 9p share tag `osecshare` at `/mnt/0sec`
- execute `/mnt/0sec/runner.sh`
- provide `/usr/bin/gcc`, libc headers, and binutils
- allow `dmesg` collection after the reproducer runs

The default kernel command line is:

```text
console=ttyS0 root=/dev/vda rw nokaslr panic=-1 init=/sbin/0sec-init
```

## CI

The real GitHub Actions E2E lane lives in `.github/workflows/kernel-validator-e2e.yml`.
It builds the VM artifacts, boots QEMU, and runs `ingest --verify` against a real
syzbot crash/reproducer pair while uploading the VM logs and runner outputs as artifacts.

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `0SEC_KERNEL_QEMU` | - | Set to `1` to enable |
| `0SEC_KERNEL_QEMU_KERNEL` | - | Path to bzImage |
| `0SEC_KERNEL_QEMU_DISK` | - | Path to rootfs.img |
| `0SEC_KERNEL_QEMU_MEMORY_MB` | `2048` | VM memory |
| `0SEC_KERNEL_QEMU_SMP` | `2` | CPU cores |
| `0SEC_KERNEL_QEMU_TIMEOUT_SEC` | `60` | Reproducer timeout |
| `0SEC_KERNEL_QEMU_BOOT_TIMEOUT_SEC` | `120` | Boot timeout |
| `0SEC_KERNEL_QEMU_ACCEL` | - | QEMU accelerator (e.g. `kvm`) |
| `0SEC_KERNEL_QEMU_SHARE_TAG` | `osecshare` | 9p mount tag used by the guest boot script |
| `0SEC_KERNEL_QEMU_ARTIFACT_DIR` | - | Preserve VM run artifacts (serial log, compile log, dmesg, runner outputs) instead of deleting the temp directory |
| `0SEC_KERNEL_BUILD_CACHE` | `~/.cache/0sec/kernel-vm` | Cache directory for `--kernel-tree` VM builds |
