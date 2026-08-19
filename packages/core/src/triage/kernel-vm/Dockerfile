# 0sec kernel crash validator — KASAN-enabled kernel builder
#
# Builds a minimal Linux kernel with KASAN + UBSAN enabled, plus a
# Debian root filesystem that boots into a shared-workdir reproducer runner.
#
# Usage:
#   docker build -t 0sec-kernel-builder -f Dockerfile .
#   docker run --rm -v $(pwd)/out:/out 0sec-kernel-builder
#
# Outputs in /out:
#   bzImage       — KASAN-enabled kernel
#   rootfs.img    — ext4 root filesystem (512MB) with GCC/binutils + 0sec-init
#   kernel.config — .config used for the build
#
# The resulting artifacts work with the kernel-vm-runner.ts QEMU config:
#   0SEC_KERNEL_QEMU=1
#   0SEC_KERNEL_QEMU_KERNEL=/path/to/bzImage
#   0SEC_KERNEL_QEMU_DISK=/path/to/rootfs.img

FROM debian:bookworm-slim AS kernel-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc-x86-64-linux-gnu \
    binutils-x86-64-linux-gnu \
    libc6-dev-amd64-cross \
    bc \
    bison \
    flex \
    libelf-dev \
    libssl-dev \
    libncurses-dev \
    wget \
    xz-utils \
    ca-certificates \
    cpio \
    kmod \
    && rm -rf /var/lib/apt/lists/*

ARG KERNEL_VERSION=6.8.12
ARG KERNEL_URL=https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz
ARG KERNEL_MAKE_JOBS=4

# Download and extract kernel source
WORKDIR /build
RUN wget -q "${KERNEL_URL}" -O linux.tar.xz \
    && tar xf linux.tar.xz \
    && rm linux.tar.xz \
    && mv linux-* linux

# Generate kernel config with KASAN + UBSAN + debug info
WORKDIR /build/linux
ENV ARCH=x86_64
ENV CROSS_COMPILE=x86_64-linux-gnu-
RUN make x86_64_defconfig \
    && scripts/config \
        --enable CONFIG_KASAN \
        --set-str CONFIG_KASAN_MODE "generic" \
        --enable CONFIG_KASAN_GENERIC \
        --enable CONFIG_KASAN_INLINE \
        --enable CONFIG_KASAN_STACK \
        --enable CONFIG_KASAN_VMALLOC \
        --enable CONFIG_UBSAN \
        --enable CONFIG_UBSAN_BOUNDS \
        --enable CONFIG_UBSAN_SHIFT \
        --enable CONFIG_UBSAN_DIV_ZERO \
        --enable CONFIG_UBSAN_BOOL \
        --enable CONFIG_UBSAN_ENUM \
        --enable CONFIG_UBSAN_ALIGNMENT \
        --enable CONFIG_KCSAN \
        --enable CONFIG_DEBUG_INFO \
        --enable CONFIG_DEBUG_INFO_DWARF5 \
        --enable CONFIG_DEBUG_KERNEL \
        --enable CONFIG_PROVE_LOCKING \
        --enable CONFIG_LOCK_STAT \
        --enable CONFIG_DEBUG_ATOMIC_SLEEP \
        --enable CONFIG_STACKTRACE \
        --enable CONFIG_RCU_CPU_STALL_TIMEOUT \
        --enable CONFIG_DETECT_HUNG_TASK \
        --enable CONFIG_DEFAULT_HUNG_TASK_TIMEOUT \
        --enable CONFIG_PANIC_ON_OOPS \
        --enable CONFIG_VIRTIO \
        --enable CONFIG_VIRTIO_PCI \
        --enable CONFIG_VIRTIO_NET \
        --enable CONFIG_VIRTIO_BLK \
        --enable CONFIG_EXT4_FS \
        --enable CONFIG_TMPFS \
        --enable CONFIG_DEVTMPFS \
        --enable CONFIG_DEVTMPFS_MOUNT \
        --enable CONFIG_NET \
        --enable CONFIG_INET \
        --enable CONFIG_NFS_FS \
        --enable CONFIG_NFSD \
        --enable CONFIG_SUNRPC \
        --enable CONFIG_BT \
        --enable CONFIG_BT_HCIUART \
        --enable CONFIG_CFG80211 \
        --enable CONFIG_MAC80211 \
        --enable CONFIG_SCTP_DEFAULT_COOKIE_HMAC_MD5 \
        --enable CONFIG_IP_SCTP \
        --enable CONFIG_9P_FS \
        --enable CONFIG_NET_9P \
        --enable CONFIG_NET_9P_VIRTIO \
        --disable CONFIG_RANDOMIZE_BASE \
        --set-val CONFIG_FRAME_WARN 2048 \
    && make olddefconfig

# Build kernel. Default to a conservative job count because this often runs
# under amd64 emulation on arm64 hosts, where `-j$(nproc)` is prone to GCC ICEs.
RUN make -j"${KERNEL_MAKE_JOBS}" bzImage

# ── Root filesystem builder ──
FROM --platform=linux/amd64 debian:bookworm-slim AS rootfs-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    debootstrap \
    e2fsprogs \
    qemu-utils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create minimal Debian rootfs
RUN mkdir -p /rootfs \
    && debootstrap --variant=minbase --include=\
openssh-server,gcc,libc6-dev,make,kmod,procps,iproute2,iputils-ping,\
net-tools,strace,util-linux,systemd-sysv \
    bookworm /rootfs http://deb.debian.org/debian

# Configure rootfs
RUN chroot /rootfs bash -c '\
    echo "root:root" | chpasswd && \
    mkdir -p /root/.ssh && \
    ssh-keygen -t ed25519 -N "" -f /root/.ssh/osec_vm_key && \
    cat /root/.ssh/osec_vm_key.pub >> /root/.ssh/authorized_keys && \
    chmod 600 /root/.ssh/authorized_keys && \
    ssh-keygen -A && \
    echo "nameserver 8.8.8.8" > /etc/resolv.conf && \
    sed -i "s/#PermitRootLogin.*/PermitRootLogin yes/" /etc/ssh/sshd_config && \
    sed -i "s/#PasswordAuthentication.*/PasswordAuthentication yes/" /etc/ssh/sshd_config && \
    apt-get update && \
    apt-get install -y --no-install-recommends gdb isc-dhcp-client binutils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    echo "0sec-kernel" > /etc/hostname && \
    mkdir -p /root/0sec-kernel \
'

RUN printf '%s\n' \
    '#!/bin/sh' \
    'mount -t proc proc /proc 2>/dev/null || true' \
    'mount -t sysfs sysfs /sys 2>/dev/null || true' \
    'mount -t devtmpfs devtmpfs /dev 2>/dev/null || true' \
    'mount -t tmpfs tmpfs /run 2>/dev/null || true' \
    'mount -t tmpfs tmpfs /tmp 2>/dev/null || true' \
    'echo "0SEC_INIT_START" > /dev/kmsg 2>/dev/null || true' \
    'mkdir -p /mnt/0sec' \
    'if mount -t 9p -o trans=virtio,version=9p2000.L osecshare /mnt/0sec 2>/tmp/0sec-mount.err; then' \
    '  echo "0SEC_INIT_SHARE_MOUNTED" > /dev/kmsg 2>/dev/null || true' \
    'else' \
    '  err=$(tr "\n" " " </tmp/0sec-mount.err 2>/dev/null || true)' \
    '  echo "0SEC_INIT_SHARE_MOUNT_FAILED:${err:-unknown}" > /dev/kmsg 2>/dev/null || true' \
    'fi' \
    'if [ -f /mnt/0sec/runner.sh ]; then' \
    '  echo "0SEC_INIT_RUNNER_START" > /dev/kmsg 2>/dev/null || true' \
    '  /bin/sh /mnt/0sec/runner.sh' \
    '  status=$?' \
    '  echo "0SEC_INIT_RUNNER_EXIT:${status}" > /dev/kmsg 2>/dev/null || true' \
    '  sync' \
    '  poweroff -f 2>/dev/null || halt -f 2>/dev/null || reboot -f 2>/dev/null || exit "$status"' \
    'fi' \
    'echo "0SEC_INIT_IDLE" > /dev/kmsg 2>/dev/null || true' \
    'sleep infinity' \
    > /rootfs/sbin/0sec-init \
    && chmod 755 /rootfs/sbin/0sec-init

# Create ext4 disk image without requiring loop-mount support inside Docker build
RUN truncate -s 512M /rootfs.img \
    && mkfs.ext4 -F -d /rootfs /rootfs.img

# ── Final output stage ──
FROM debian:bookworm-slim

COPY --from=kernel-builder /build/linux/arch/x86/boot/bzImage /artifacts/bzImage
COPY --from=kernel-builder /build/linux/.config /artifacts/kernel.config
COPY --from=rootfs-builder /rootfs.img /artifacts/rootfs.img
COPY --from=rootfs-builder /rootfs/root/.ssh/osec_vm_key /artifacts/osec_vm_key
COPY --from=rootfs-builder /rootfs/root/.ssh/osec_vm_key.pub /artifacts/osec_vm_key.pub

# Output script: copy artifacts to /out volume with host-friendly ownership.
CMD ["sh", "-c", "\
set -eu; \
uid=${HOST_UID:-0}; gid=${HOST_GID:-0}; \
install -o \"$uid\" -g \"$gid\" -m 0644 /artifacts/bzImage /out/bzImage; \
install -o \"$uid\" -g \"$gid\" -m 0644 /artifacts/kernel.config /out/kernel.config; \
install -o \"$uid\" -g \"$gid\" -m 0644 /artifacts/rootfs.img /out/rootfs.img; \
install -o \"$uid\" -g \"$gid\" -m 0600 /artifacts/osec_vm_key /out/osec_vm_key; \
install -o \"$uid\" -g \"$gid\" -m 0644 /artifacts/osec_vm_key.pub /out/osec_vm_key.pub; \
echo 'Kernel VM artifacts exported to /out/'; \
ls -lh /out/ \
"]
