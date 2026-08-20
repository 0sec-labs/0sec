# 0verse engine image — bundles the free, redistributable analysis toolchain so
# `docker run ghcr.io/0sec-labs/0verse run <binary>` works with no host setup.
#   Ghidra (Apache-2.0, headless decompiler)  +  angr (symbolic)  +  AFL++ (fuzzing)
#   + GDB (optional trusted-local runtime reach probes; ptrace remains opt-in)
# Binary Ninja is never bundled (proprietary) — it's an optional host adapter.
#
# JDK 21 base (Ghidra 12.x requires it); Ubuntu noble for python3.12 + afl++.
# Pinned to amd64: Ghidra ships a decompiler executable only for linux_x86_64
# (no linux_arm_64), so the image must be x86_64 (runs under emulation on ARM).

# --- stage 1: afl-qemu-trace (#316) -----------------------------------------
# Ubuntu's afl++ package ships afl-fuzz but NOT afl-qemu-trace: qemu_mode is an
# out-of-tree build. Without it zeroverse.fuzz.aflpp.afl_qemu_available() is
# False, and since fuzz/orchestrator.py builds AflConfig(qemu_mode=True) for
# anything that is not a natively instrumented driver, EVERY stripped /
# non-instrumented ELF — 0verse's actual product surface — silently degrades to
# "no fuzz lane" and the scan reports a clean zero. Build it here.
#
# Why only afl-qemu-trace and not all of AFL++ from source:
#   * afl-qemu-trace is a leaf. Nothing links it; afl-fuzz just execs it.
#   * The apt afl++ also provides afl-clang-fast / afl-gcc-fast and an
#     afl-compiler-rt built against this distro's clang (clang + libclang-rt-*
#     below). Rebuilding AFL++ from source would have to reproduce that pairing
#     and would ADD a skew axis (source compiler-rt vs distro clang) rather than
#     remove one.
#   * "Matched by construction" is worth less than a gate that fails the build.
#     The final stage hard-checks the installed afl-fuzz banner against
#     AFL_VERSION, so skew is a loud build failure, never a runtime degrade.
#     This is the #313 class: afl-fuzz 4.09c against an older afl-compiler-rt
#     whose at_exit did kill(child,9) with no _exit, so the fork server survived
#     afl-fuzz's SIGTERM and afl-fuzz deadlocked in waitpid. Cost: a full day.
#
# Bump AFL_VERSION only together with the apt afl++ package (noble ships
# 4.09c-1ubuntu3). Same base image as the runtime stage so the built binary
# links the exact glibc it will run against.
#
# Cost: ~2 min wall on a 6-core cap (apt 30s, clones 25s, AFL++ core 10s, the
# qemu compile 60s), and none of the ~860 MB build tree reaches the runtime
# layer — only the 4.9 MB afl-qemu-trace is copied over. The stage runs
# concurrently with the Ghidra download and the pip install under buildkit, and
# image-publish.yml already caches it (cache-to: type=gha,mode=max), so a build
# that does not move AFL_VERSION or the base image pays nothing.
FROM --platform=linux/amd64 eclipse-temurin:21-jdk-noble AS afl-qemu-builder

ARG AFL_VERSION=4.09c
# Cap the qemu compile (build_qemu_support.sh hardcodes `make -j$(nproc)`).
# Empty = use every core. Set it when building on a box with other work on it.
ARG AFL_QEMU_JOBS=

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates build-essential \
        ninja-build meson pkg-config \
        libglib2.0-dev libpixman-1-dev \
        python3 python3-dev \
    && rm -rf /var/lib/apt/lists/*

# AFL++ source at the pinned tag. include/config.h carries the version the
# forkserver protocol constants come from — assert it rather than trust the tag.
RUN set -eux; \
    git clone --depth 1 --branch "v${AFL_VERSION}" \
        https://github.com/AFLplusplus/AFLplusplus.git /opt/aflplusplus; \
    grep -q "define VERSION \"++${AFL_VERSION}\"" /opt/aflplusplus/include/config.h

# qemuafl, cloned FULL on purpose. build_qemu_support.sh runs
#   git checkout "$(cat qemu_mode/QEMUAFL_VERSION)"
# and on a shallow clone that commit is not present, so the checkout degrades to
# a printed *warning* plus master HEAD — reintroducing version skew through the
# back door while still exiting 0. Verify the pin is fetched before building.
# (The v4.09c tag records the pin twice, gitlink b0abbe2e vs QEMUAFL_VERSION
# a1321713c7; `git diff a1321713c7..b0abbe2e` is empty, so it is a non-issue.)
RUN set -eux; \
    git clone https://github.com/AFLplusplus/qemuafl \
        /opt/aflplusplus/qemu_mode/qemuafl; \
    pin="$(cat /opt/aflplusplus/qemu_mode/QEMUAFL_VERSION)"; \
    git -C /opt/aflplusplus/qemu_mode/qemuafl cat-file -e "${pin}^{commit}"; \
    echo "qemuafl pin: ${pin}"

# build_qemu_support.sh refuses to run without ../afl-showmap, and re-runs a
# plain `make` in the source root for its own instrumentation self-test.
RUN set -eux; \
    jobs="${AFL_QEMU_JOBS:-$(nproc)}"; \
    make -C /opt/aflplusplus -j"${jobs}" afl-showmap afl-fuzz afl-gotcpu

RUN set -eux; \
    jobs="${AFL_QEMU_JOBS:-$(nproc)}"; \
    shim="$(mktemp -d)"; \
    printf '#!/bin/sh\necho %s\n' "${jobs}" > "${shim}/nproc"; \
    chmod +x "${shim}/nproc"; \
    cd /opt/aflplusplus/qemu_mode && PATH="${shim}:${PATH}" ./build_qemu_support.sh; \
    rm -rf "${shim}"; \
    test -x /opt/aflplusplus/afl-qemu-trace

# --- stage 2: the engine image ----------------------------------------------
FROM --platform=linux/amd64 eclipse-temurin:21-jdk-noble

ARG GHIDRA_VERSION=12.1.2
ARG GHIDRA_DATE=20260605
# Must equal the afl++ version apt installs below; enforced at the end of this
# stage. Keep in sync with the ARG of the same name in afl-qemu-builder.
ARG AFL_VERSION=4.09c

ENV DEBIAN_FRONTEND=noninteractive \
    GHIDRA_HOME=/opt/ghidra \
    GHIDRA_INSTALL_DIR=/opt/ghidra \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:/opt/ghidra/support:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-dev \
        wget unzip ca-certificates openssh-client \
        afl++ qemu-user libglib2.0-0t64 \
        clang llvm lld libclang-rt-17-dev libclang-rt-18-dev \
        electric-fence \
        build-essential gdb \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv "$VIRTUAL_ENV"

# Ghidra headless.
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" "$GHIDRA_HOME" \
    && rm /tmp/ghidra.zip

# PyGhidra (CPython driver for Ghidra) — install the wheel bundled with Ghidra,
# which is authoritative because it is version-matched to GHIDRA_VERSION above.
# The `ghidra` extra in pyproject.toml pins the same version from PyPI for bare
# hosts; bump both together when GHIDRA_VERSION moves (see docs/GHIDRA-SETUP.md).
RUN pip install --no-cache-dir "$GHIDRA_HOME"/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY conf ./conf
COPY docker ./docker
COPY tests/fixtures/windows_ioctl_wdm.c /opt/0verse-fixtures/windows_ioctl_wdm.c
COPY tests/fixtures/windows_ioctl_wdm_patched.c /opt/0verse-fixtures/windows_ioctl_wdm_patched.c
COPY tests/fixtures/windows_ioctl_wdm_fixed.c /opt/0verse-fixtures/windows_ioctl_wdm_fixed.c
COPY tests/fixtures/native_lastmile_reach.c /opt/0verse-fixtures/native_lastmile_reach.c
COPY tests/fixtures/native_lastmile_png.c /opt/0verse-fixtures/native_lastmile_png.c
COPY tests/fixtures/shared_library_harness_vuln.c /opt/0verse-fixtures/shared_library_harness_vuln.c
COPY tests/fixtures/shared_library_harness_fixed.c /opt/0verse-fixtures/shared_library_harness_fixed.c
COPY scripts/browser/replay-candidate.py ./scripts/browser/replay-candidate.py
COPY docker/native_lastmile_e2e.py ./docker/native_lastmile_e2e.py

# Engine extras (angr/lief/capa/pwntools) + the package itself, into the venv.
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e ".[analyze,symbolic,poc,llm]"

# afl-qemu-trace from stage 1. Placed after the Ghidra/pip work on purpose so
# buildkit runs the qemu compile concurrently with it instead of behind it.
#
# Layout is what aflpp.afl_qemu_trace_path() actually looks for:
#   host arch  -> which("afl-qemu-trace"), then /usr/lib/afl, /usr/local/lib/afl
#   per-CPU    -> $ZEROVERSE_AFL_QEMU_<CPU>, which("afl-qemu-trace-<cpu>"), then
#                 /usr/local/bin, /usr/bin, /usr/lib/afl, /usr/local/lib/afl
# /usr/local/bin satisfies both and is also on afl-fuzz's own find_afl_binary()
# search path; /usr/local/lib/afl is upstream's default AFL_PATH, kept as a
# fallback for callers that scrub PATH. Deliberately NOT /usr/lib/afl — that
# directory is dpkg-owned by the afl++ package. AFL_PATH is left unset because
# _prepare_cross_afl_path() sets it per-run for cross-arch targets.
COPY --from=afl-qemu-builder /opt/aflplusplus/afl-qemu-trace /usr/local/bin/afl-qemu-trace
RUN set -eux; \
    install -d /usr/local/lib/afl; \
    install -m 0755 /usr/local/bin/afl-qemu-trace /usr/local/lib/afl/afl-qemu-trace; \
    ln -sf /usr/local/bin/afl-qemu-trace /usr/local/bin/afl-qemu-trace-x86_64

# Hard version gate + capability assertions. Everything below fails the BUILD
# rather than letting a scan report a silent zero at runtime (#296/#297/#304).
RUN set -eux; \
    have="$( { afl-fuzz -h 2>&1 || true; } | sed -e 's/\x1b\[[0-9;]*m//g' \
             | grep -oE 'afl-fuzz\+\+[0-9a-z.]+' | head -1 \
             | sed 's/afl-fuzz++//' || true )"; \
    echo "apt afl-fuzz: ${have:-<none>}   afl-qemu-trace built from: ${AFL_VERSION}"; \
    if [ "${have}" != "${AFL_VERSION}" ]; then \
        echo "REFUSING: apt afl-fuzz is '${have:-<none>}' but afl-qemu-trace was built" >&2; \
        echo "from AFLplusplus v${AFL_VERSION}. A skewed pair breaks the forkserver (#313)." >&2; \
        echo "Bump AFL_VERSION (both stages) to the tag matching the apt package." >&2; \
        exit 1; \
    fi; \
    afl-qemu-trace --version | head -1; \
    python -c "import sys; from zeroverse.fuzz.aflpp import afl_qemu_available; \
sys.exit(0 if afl_qemu_available() else 'afl_qemu_available() is False')"; \
    python -c "import sys; from zeroverse.fuzz.coverage import qemu_user_bin; \
sys.exit(0 if qemu_user_bin() else 'qemu_user_bin() is None')"

# Prove the lane, don't just prove the file exists. The version gate above and
# build_qemu_support.sh's own afl-showmap self-test both use the SOURCE-built
# binaries; the pairing that actually ships — apt afl-fuzz driving the built
# afl-qemu-trace over the forkserver protocol — is only exercised here. That
# handshake is exactly what #313 broke, and it fails as a HANG, so a
# `-V` bounded run plus an execs floor is the honest check.
# AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES makes this independent of the build
# host's kernel.core_pattern (#312); the smoke target never crashes, so nothing
# is silently skipped by setting it.
RUN set -eux; \
    printf '%s\n' \
      '#include <stdio.h>' \
      'int main(void){unsigned char b[64];size_t n=fread(b,1,63,stdin);b[n]=0;' \
      'if(n>1&&b[0]==0x41)return 2; if(n>1&&b[0]==0x42)return 3; return 0;}' \
      > /tmp/qsmoke.c; \
    gcc -O1 -o /tmp/qsmoke /tmp/qsmoke.c; \
    strip /tmp/qsmoke; \
    mkdir -p /tmp/qsmoke-in; printf hello > /tmp/qsmoke-in/seed; \
    AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 AFL_NO_UI=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
      afl-fuzz -Q -i /tmp/qsmoke-in -o /tmp/qsmoke-out -m none -V 15 \
      -- /tmp/qsmoke > /tmp/qsmoke.log 2>&1 || true; \
    stats=/tmp/qsmoke-out/default/fuzzer_stats; \
    if [ ! -f "$stats" ]; then tail -40 /tmp/qsmoke.log >&2; \
        echo "QEMU-mode smoke produced no fuzzer_stats" >&2; exit 1; fi; \
    grep -E '^(execs_done|execs_per_sec|target_mode|afl_version)' "$stats"; \
    execs="$(awk '/^execs_done/{print $3}' "$stats")"; \
    mode="$(sed -n 's/^target_mode *: *//p' "$stats")"; \
    if [ "${execs:-0}" -le 100 ]; then tail -40 /tmp/qsmoke.log >&2; \
        echo "QEMU-mode smoke did ${execs:-0} execs — the forkserver did not run" >&2; \
        exit 1; fi; \
    case "$mode" in *qemu*) ;; \
        *) echo "afl-fuzz reported target_mode='${mode}', expected qemu" >&2; exit 1;; \
    esac; \
    rm -rf /tmp/qsmoke /tmp/qsmoke.c /tmp/qsmoke-in /tmp/qsmoke-out /tmp/qsmoke.log

ENTRYPOINT ["0verse"]
CMD ["--help"]
