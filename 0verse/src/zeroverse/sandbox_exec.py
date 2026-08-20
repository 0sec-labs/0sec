"""Sandboxed target execution — the oracle's isolation seam.

The oracles (:mod:`oracle`) must *run* the analysis target to classify anything.
Historically that meant a native ``subprocess`` on the analysis host — fine for
trusted fixtures, but the whole point of the dynamic stage is executing
*untrusted, possibly-malicious* inputs and binaries (PoV candidates, fuzz
finds, ARVO reproducers). This module puts that execution behind one seam:

  * :class:`LocalExecutor` — exactly the historical behavior (``subprocess.run``
    with the host environment merged in), available only when explicitly selected.
  * :class:`MsbSshExecutor` — runs the target inside a **microsandbox microVM**
    (libkrun/KVM) on a remote host over ssh, mirroring
    :class:`zeroverse.kernel.runner.SshFleetRunner`'s pattern. Every verdict gets
    a fresh microVM, a digest-pinned image and msb binary, root-owned staged
    artifacts, and an unprivileged target process. The microVM is removed after
    the verdict so one sample cannot poison another.

PoV-is-truth is preserved: an infrastructure failure (ssh down, sandbox dead,
no completion sentinel) is reported as :attr:`ExecResult.error` and maps to a
non-crashed ``RunResult`` carrying the error string — the exact convention the
oracle already uses for ``OSError`` — and is never conflated with "ran clean".
Selection is via ``ZEROVERSE_EXECUTOR=local|msb`` (no default; execution fails
closed until explicitly authorized); the msb
backend is tuned by ``ZEROVERSE_MSB_HOST`` (default ``fuzzer``),
``ZEROVERSE_MSB_IMAGE`` (a digest-pinned Ubuntu 24.04 image by default),
``ZEROVERSE_MSB_SHA256`` (the expected remote msb binary digest), and
``ZEROVERSE_MSB_SANDBOX`` (an identity prefix; each run derives a fresh name).

Scope honesty: this is a *confirmation-grade* seam (tens of runs per finding),
not a fuzzing-throughput path — the fuzzers keep their own native loops.
Architecture note: a microsandbox guest runs its host's arch — x86_64 ASan
targets need an x86_64 msb host (``fuzzer``); an Apple-silicon Mac host runs
arm64 guests only (no Rosetta in msb 0.6.6 — measured ENOEXEC).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .cancellation import CancelledError, RunContext, run_process

# Guest-side layout inside the warm sandbox.
GUEST_BIN_DIR = "/work/bin"
GUEST_IN_DIR = "/work/in"

# Outer ssh grace on top of the in-sandbox ``timeout -s KILL``: covers image
# pull on first use, sandbox creation, cp round-trips, and network jitter.
SSH_GRACE_S = 120.0
DEFAULT_MSB_IMAGE = (
    "ubuntu@sha256:52df9b1ee71626e0088f7d400d5c6b5f7bb916f8f0c82b474289a4ece6cf3faf"
)
DEFAULT_MSB_SHA256 = "75d72e02b758229ee95f7f9d4e8893f0410c53ee379fdf6e076e49fc8080b975"
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_PINNED_IMAGE_RE = re.compile(r"\S+@sha256:[0-9a-f]{64}")


def guest_target_error(data: bytes) -> str:
    """Return why bytes cannot execute in the pinned x86-64 Linux guest."""
    if data.startswith(b"#!"):
        return ""
    if not data.startswith(b"\x7fELF"):
        return "remote execution requires an x86-64 ELF or shebang script"
    if len(data) < 20:
        return "remote ELF target has a truncated header"
    if data[4] != 2 or data[5] != 1:
        return "remote ELF target must be 64-bit little-endian"
    machine = int.from_bytes(data[18:20], "little")
    if machine != 62:
        return f"remote ELF target architecture is unsupported (e_machine={machine})"
    return ""


def guest_target_supports_preload(data: bytes) -> bool:
    """Whether the target is interpreter-backed, so LD_PRELOAD can affect it."""
    if data.startswith(b"#!"):
        return True
    if guest_target_error(data) or len(data) < 64:
        return False
    phoff = int.from_bytes(data[32:40], "little")
    phentsize = int.from_bytes(data[54:56], "little")
    phnum = int.from_bytes(data[56:58], "little")
    if phentsize < 4 or phnum > 1024:
        return False
    return any(
        offset + 4 <= len(data) and int.from_bytes(data[offset : offset + 4], "little") == 3
        for offset in (phoff + index * phentsize for index in range(phnum))
    )


@dataclass
class ExecResult:
    """One target execution. ``returncode`` follows ``subprocess`` semantics
    (negative = killed by signal). ``timed_out``/``error`` are distinct honest
    states: timeout means the *target* outran its budget; ``error`` means the
    infrastructure never produced a verdict — callers must not read it as a
    clean run. Under :class:`MsbSshExecutor` stdout/stderr arrive combined on
    ``stderr`` (the guest command runs under ``2>&1``; the oracles scan stderr
    only, so nothing they consume is lost)."""

    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: str = ""
    provenance: dict[str, str] = field(default_factory=dict)
    cancelled: bool = False


class Executor(Protocol):
    """Run ``argv`` once with ``stdin`` and explicit ``env``, bounded by
    ``timeout`` seconds, and classify the outcome. ``env`` is *explicit* env
    only; an executor decides what to merge from its own environment
    (:class:`LocalExecutor` merges ``os.environ``; a remote executor cannot
    meaningfully do so)."""

    def run(
        self,
        argv: list[str],
        *,
        stdin: bytes = b"",
        env: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> ExecResult: ...


class LocalExecutor:
    """Native execution with a run-local process-group cancellation boundary."""

    def __init__(self, context: RunContext | None = None) -> None:
        self._context = context

    def for_context(self, context: RunContext) -> LocalExecutor:
        return LocalExecutor(context)

    def run(
        self,
        argv: list[str],
        *,
        stdin: bytes = b"",
        env: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> ExecResult:
        full_env = {**os.environ, **(env or {})}
        result = run_process(
            argv,
            input=stdin,
            env=full_env,
            timeout=timeout,
            context=self._context,
        )
        return ExecResult(
            returncode=result.returncode,
            stdout=result.stdout.decode("utf-8", "replace"),
            stderr=result.stderr.decode("utf-8", "replace"),
            timed_out=result.timed_out,
            error=result.error,
            cancelled=result.cancelled,
        )


class DisabledExecutor:
    """Fail closed until the operator explicitly selects an execution boundary."""

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def run(
        self,
        argv: list[str],
        *,
        stdin: bytes = b"",
        env: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> ExecResult:
        del argv, stdin, env, timeout
        return ExecResult(error=self.reason, stderr=self.reason)


# --- MsbSshExecutor pure pieces (unit-testable without ssh/msb) --------------

_STATUS_RE = r"^0VERSE-STATUS-{canary}:(E|S):(\d+)$"
_TIMEOUT_RE = r"^0VERSE-STATUS-{canary}:T$"
_EXEC_ERROR_RE = r"^0VERSE-STATUS-{canary}:X:(\d+)$"
_MSBC_RE = r"^0VERSE-MSBEXEC-{canary}:(\d+)$"


def rc_sentinel(canary: str) -> str:
    return f"0VERSE-STATUS-{canary}"


def parse_exec_output(
    text: str, canary: str
) -> tuple[int | None, bool, str, str]:
    """Parse final guest and host status lines without trusting target output."""
    escaped = re.escape(canary)
    status_re = re.compile(_STATUS_RE.format(canary=escaped), re.MULTILINE)
    timeout_re = re.compile(_TIMEOUT_RE.format(canary=escaped), re.MULTILINE)
    exec_error_re = re.compile(_EXEC_ERROR_RE.format(canary=escaped), re.MULTILINE)
    outer_re = re.compile(_MSBC_RE.format(canary=escaped), re.MULTILINE)
    statuses = list(status_re.finditer(text))
    timeouts = list(timeout_re.finditer(text))
    exec_errors = list(exec_error_re.finditer(text))
    outers = list(outer_re.finditer(text))
    cleaned = status_re.sub(
        "", timeout_re.sub("", exec_error_re.sub("", outer_re.sub("", text)))
    ).strip()
    if not outers:
        return None, False, cleaned, "missing host completion status"
    outer_rc = int(outers[-1].group(1))
    if outer_rc != 0:
        return None, False, cleaned, f"msb exec exited {outer_rc}"
    if exec_errors:
        return (
            None,
            False,
            cleaned,
            f"guest exec failed with errno {exec_errors[-1].group(1)}",
        )
    final_status_pos = statuses[-1].start() if statuses else -1
    final_timeout_pos = timeouts[-1].start() if timeouts else -1
    if final_timeout_pos > final_status_pos:
        return 0, True, cleaned, ""
    if not statuses:
        return None, False, cleaned, "missing guest completion status"
    kind, raw = statuses[-1].groups()
    value = int(raw)
    if kind == "S":
        if value <= 0:
            return None, False, cleaned, "invalid guest signal status"
        return -value, False, cleaned, ""
    if value > 255:
        return None, False, cleaned, "invalid guest exit status"
    return value, False, cleaned, ""


def build_exec_command(
    guest_argv: list[str],
    *,
    env: dict[str, str] | None,
    timeout: float,
    canary: str,
    stdin_guest_path: str | None,
) -> str:
    """Build the root-owned supervisor command for an ephemeral guest.

    The supervisor drops the target to uid/gid 65534 and reads the raw wait
    status, keeping an explicit exit 139 distinct from a real SIGSEGV.
    """
    redirect = f" < {shlex.quote(stdin_guest_path)}" if stdin_guest_path else ""
    quoted = " ".join(shlex.quote(a) for a in guest_argv)
    t = max(1, int(timeout))
    env_setup = ""
    for key, value in (env or {}).items():
        if "\x00" in key or "=" in key or "\x00" in value:
            raise ValueError("invalid target environment")
        key_hex = key.encode().hex()
        value_hex = value.encode().hex()
        env_setup += (
            f'$ENV{{pack("H*","{key_hex}")}}=pack("H*","{value_hex}"); '
        )
    supervisor = (
        "use POSIX qw(:sys_wait_h setgid setuid); use Fcntl qw(F_SETFD FD_CLOEXEC); "
        "my $budget=shift @ARGV; pipe(my $er,my $ew) or die 'pipe failed'; "
        "fcntl($ew,F_SETFD,FD_CLOEXEC) or die 'fcntl failed'; "
        f"my $outpath='/tmp/0v-output-{canary}'; "
        "open(my $out,'>',$outpath) or die 'output open failed'; chmod 0600,$outpath; "
        "my $pid=fork(); die 'fork failed' unless defined $pid; "
        "if ($pid==0) { close $er; "
        "my $fail=sub {my $code=shift; syswrite($ew,$code); exit 127;}; "
        "open(STDOUT,'>&',$out) or $fail->(9001); "
        "open(STDERR,'>&',$out) or $fail->(9002); close $out; "
        "defined(setpgrp(0,0)) or $fail->(9003); "
        "syscall(116,0,0)==0 or $fail->(9004); "
        "syscall(157,38,1,0,0,0)==0 or $fail->(9005); "
        "setgid(65534)==0 or $fail->(9006); setuid(65534)==0 or $fail->(9007); "
        f"{env_setup}exec {{$ARGV[0]}} @ARGV; "
        "my $eno=0+$!; syswrite($ew,$eno); exit 127; } "
        "close $ew; close $out; "
        "my $timed=0; local $SIG{ALRM}=sub {$timed=1; kill 9,-$pid;}; "
        "alarm($budget); waitpid($pid,0); alarm(0); my $st=$?; kill 9,-$pid; "
        "my $cleanup=system('/usr/bin/pkill','-KILL','-u','65534'); "
        "my $execerr=''; sysread($er,$execerr,32); close $er; "
        "$execerr=9008 if $cleanup==-1 && $execerr eq ''; "
        "open(my $readout,'<',$outpath) or die 'output read failed'; "
        "local $/; my $captured=<$readout> // ''; close $readout; print STDERR $captured; "
        f"if ($execerr ne '') {{print STDERR qq(\\n{rc_sentinel(canary)}:X:$execerr\\n);}} "
        f"if ($timed) {{print STDERR qq(\\n{rc_sentinel(canary)}:T\\n);}} "
        f"elsif ($execerr ne '') {{}} elsif (WIFSIGNALED($st)) "
        f"{{print STDERR qq(\\n{rc_sentinel(canary)}:S:)"
        ".WTERMSIG($st).qq(\\n);} "
        f"else {{print STDERR qq(\\n{rc_sentinel(canary)}:E:)"
        ".WEXITSTATUS($st).qq(\\n);}"
    )
    return (
        f"perl -e {shlex.quote(supervisor)} -- {t} {quoted}{redirect} 2>&1"
    )


def build_run_script(
    *,
    sandbox: str,
    image: str,
    guest_argv: list[str],
    staged_files: dict[str, bytes],
    env: dict[str, str] | None,
    timeout: float,
    canary: str,
    stdin_guest_path: str | None,
    expected_msb_sha256: str,
) -> str:
    """Build a fail-closed, per-run-ephemeral remote execution script.

    Every ``msb`` invocation carries ``< /dev/null``: ``bash -s`` reads the
    script itself from stdin, and an ``msb exec`` inheriting that fd would
    slurp the remainder of the script (measured live: empty output, rc 0)."""
    if _SHA256_RE.fullmatch(expected_msb_sha256) is None:
        raise ValueError("expected msb SHA-256 must be lowercase hex")
    msb = '${MSB_BIN:-$(command -v msb || echo "$HOME/.local/bin/msb")}'
    lines = [
        "set -euo pipefail",
        f"MSB={msb}",
        f"SB={shlex.quote(sandbox)}",
        f"EXPECTED_MSB_SHA256={expected_msb_sha256}",
        'ACTUAL_MSB_SHA256=$(sha256sum "$MSB" | cut -d" " -f1)',
        'test "$ACTUAL_MSB_SHA256" = "$EXPECTED_MSB_SHA256"',
        'D=$(mktemp -d /tmp/0vmsb.XXXXXX)',
        "cleanup() {",
        '  "$MSB" remove -f -q "$SB" >/dev/null 2>&1 </dev/null || true',
        '  rm -rf "$D"',
        "}",
        "trap cleanup EXIT",
        f'"$MSB" run -d {shlex.quote(image)} --name "$SB" >/dev/null </dev/null',
        f'"$MSB" exec "$SB" -- mkdir -p {GUEST_BIN_DIR} {GUEST_IN_DIR} </dev/null',
        '"$MSB" exec "$SB" -- test -x /usr/bin/pkill </dev/null',
    ]
    for i, (guest_path, data) in enumerate(staged_files.items()):
        if re.fullmatch(r"/work/(?:bin|in)/[A-Za-z0-9._-]+", guest_path) is None:
            raise ValueError(f"unsafe guest staging path: {guest_path!r}")
        b64 = base64.b64encode(data).decode()
        lines += [
            f"base64 -d > \"$D/f{i}\" <<'0VERSE-B64'",
            b64,
            "0VERSE-B64",
            f'"$MSB" cp "$D/f{i}" "$SB:{guest_path}" </dev/null',
            f'"$MSB" exec "$SB" -- chown 0:0 {guest_path} </dev/null',
            f'"$MSB" exec "$SB" -- chmod 0555 {guest_path} </dev/null',
            f'GUEST_SHA=$("$MSB" exec "$SB" -- sha256sum {guest_path} '
            '</dev/null | cut -d" " -f1)',
            f'test "$GUEST_SHA" = "{hashlib.sha256(data).hexdigest()}"',
        ]
    preload = (env or {}).get("LD_PRELOAD", "")
    for component in re.split(r"[:\s]+", preload):
        if not component:
            continue
        smoke = f"LD_PRELOAD={shlex.quote(component)} /bin/true"
        lines += [
            "set +e",
            f'LOAD_OUT=$("$MSB" exec "$SB" -- sh -c {shlex.quote(smoke)} '
            "</dev/null 2>&1); LOAD_RC=$?",
            "set -e",
            'test "$LOAD_RC" -eq 0',
            'test -z "$LOAD_OUT"',
        ]
    inner = build_exec_command(
        guest_argv, env=env, timeout=timeout, canary=canary,
        stdin_guest_path=stdin_guest_path,
    )
    lines += [
        "set +e",
        f'OUT=$("$MSB" exec "$SB" -- sh -c {shlex.quote(inner)} </dev/null 2>&1); MRC=$?',
        "set -e",
        'printf "%s\\n" "$OUT"',
        f'echo "0VERSE-MSBEXEC-{canary}:$MRC"',
    ]
    return "\n".join(lines) + "\n"


class MsbSshExecutor:
    """Run each target invocation in a fresh microsandbox on a remote KVM host.

    Staging rule: any ``argv`` element naming an existing *local* file is
    shipped into the sandbox and rewritten to its guest path (``argv[0]`` —
    the target binary — content-addressed under ``/work/bin/<sha256>`` and
    shipped on every run; everything else — e.g. the oracle's temp ``poc.bin``
    — rides the same fail-closed script). The sandbox is removed after the
    verdict, preventing one untrusted sample from poisoning another.
    """

    def __init__(
        self,
        host: str = "fuzzer",
        *,
        image: str = DEFAULT_MSB_IMAGE,
        sandbox: str = "0verse-oracle",
        ssh: str = "ssh",
        connect_timeout: int = 10,
        expected_msb_sha256: str = DEFAULT_MSB_SHA256,
        context: RunContext | None = None,
    ) -> None:
        self.host = host
        self.image = image
        self.sandbox = sandbox
        self.ssh = ssh
        self.connect_timeout = connect_timeout
        self.expected_msb_sha256 = expected_msb_sha256
        self._context = context

    def for_context(self, context: RunContext) -> MsbSshExecutor:
        return MsbSshExecutor(
            self.host,
            image=self.image,
            sandbox=self.sandbox,
            ssh=self.ssh,
            connect_timeout=self.connect_timeout,
            expected_msb_sha256=self.expected_msb_sha256,
            context=context,
        )

    # -- infra ---------------------------------------------------------------

    def _ssh(self, script: str, timeout: float) -> subprocess.CompletedProcess[bytes]:
        argv = [
            self.ssh,
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={self.connect_timeout}",
            self.host,
            "bash",
            "-s",
        ]
        result = run_process(
            argv,
            input=script.encode(),
            timeout=timeout,
            context=self._context,
        )
        if result.cancelled:
            raise CancelledError(result.error)
        if result.timed_out:
            raise subprocess.TimeoutExpired(argv, timeout)
        if result.error:
            raise OSError(result.error)
        return subprocess.CompletedProcess(
            argv,
            result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    def available(self) -> tuple[bool, str]:
        if shutil.which(self.ssh) is None:
            return False, f"{self.ssh} not on PATH"
        if _PINNED_IMAGE_RE.fullmatch(self.image) is None:
            return False, "microsandbox image must be pinned by OCI digest"
        if _SHA256_RE.fullmatch(self.expected_msb_sha256) is None:
            return False, "expected msb SHA-256 must be lowercase hex"
        try:
            script = (
                'MSB=${MSB_BIN:-$(command -v msb || echo "$HOME/.local/bin/msb")}; '
                'test -x "$MSB"; sha256sum "$MSB" | cut -d" " -f1'
            )
            p = self._ssh(script, 30)
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, f"ssh {self.host} failed: {type(e).__name__}"
        if p.returncode == 255:  # ssh itself failed (unreachable, auth, ...)
            return False, f"ssh {self.host} failed: {p.stderr.decode('utf-8', 'replace')[:200]}"
        if p.returncode != 0:
            return False, f"{self.host}: msb not found (install microsandbox there)"
        actual = p.stdout.decode("ascii", "replace").strip()
        if actual != self.expected_msb_sha256:
            return False, f"{self.host}: msb SHA-256 mismatch"
        return True, "ok"

    def build_shared_object(
        self, source: bytes, *, link_dl: bool = False
    ) -> tuple[bytes, str]:
        """Build one trusted internal preload shim for the x86-64 guest.

        Compilation happens on the Linux msb host, not on the analysis Mac. The
        resulting ELF bytes and exact compiler digest are returned so the caller
        can cache and later stage the artifact by content hash.
        """
        encoded = base64.b64encode(source).decode()
        link = " -ldl" if link_dl else ""
        script = "\n".join(
            [
                "set -euo pipefail",
                "D=$(mktemp -d /tmp/0vbuild.XXXXXX)",
                'trap \'rm -rf "$D"\' EXIT',
                "base64 -d > \"$D/shim.c\" <<'0VERSE-SOURCE'",
                encoded,
                "0VERSE-SOURCE",
                "CC=$(command -v cc || command -v gcc || command -v clang)",
                'CC_REAL=$(readlink -f "$CC")',
                'CC_SHA=$(sha256sum "$CC_REAL" | cut -d" " -f1)',
                f'"$CC" -O0 -fPIC -shared -o "$D/shim.so" "$D/shim.c"{link}',
                'printf "0VERSE-COMPILER-SHA:%s\\n" "$CC_SHA"',
                'base64 -w0 "$D/shim.so"',
                "printf '\\n'",
            ]
        )
        try:
            result = self._ssh(script + "\n", 90)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise OSError(f"remote preload build failed: {exc}") from exc
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace")[:300]
            raise OSError(f"remote preload build exited {result.returncode}: {detail}")
        try:
            lines = result.stdout.decode("ascii", "strict").splitlines()
        except UnicodeDecodeError as exc:
            raise OSError("remote preload build returned non-ASCII receipt bytes") from exc
        if len(lines) != 2 or not lines[0].startswith("0VERSE-COMPILER-SHA:"):
            raise OSError("remote preload build returned an invalid receipt")
        compiler_sha = lines[0].removeprefix("0VERSE-COMPILER-SHA:")
        if _SHA256_RE.fullmatch(compiler_sha) is None:
            raise OSError("remote preload build returned an invalid compiler digest")
        try:
            artifact = base64.b64decode(lines[1], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise OSError("remote preload build returned invalid artifact bytes") from exc
        compatibility_error = guest_target_error(artifact)
        if compatibility_error:
            raise OSError(f"remote preload build produced incompatible ELF: {compatibility_error}")
        return artifact, compiler_sha

    # -- the seam --------------------------------------------------------------

    def run(
        self,
        argv: list[str],
        *,
        stdin: bytes = b"",
        env: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> ExecResult:
        if not argv:
            return ExecResult(error="empty argv", stderr="empty argv")
        canary = os.urandom(6).hex()  # per-run: unpredictable, namespaces staged paths
        if _PINNED_IMAGE_RE.fullmatch(self.image) is None:
            error = "microsandbox image must be pinned by OCI digest"
            return ExecResult(error=error, stderr=error)
        if _SHA256_RE.fullmatch(self.expected_msb_sha256) is None:
            error = "expected msb SHA-256 must be lowercase hex"
            return ExecResult(error=error, stderr=error)
        try:
            guest_argv = list(argv)
            guest_env = dict(env or {})
            identity_env = dict(env or {})
            staged: dict[str, bytes] = {}
            invocation_argv: list[dict[str, str]] = []
            input_files: list[str] = []
            env_files: list[str] = []
            env_build_receipts: list[dict[str, str]] = []
            target = Path(argv[0])
            if not target.is_file():
                error = "remote execution requires an existing local target file"
                return ExecResult(error=error, stderr=error)
            target_data = target.read_bytes()
            compatibility_error = guest_target_error(target_data)
            if compatibility_error:
                return ExecResult(error=compatibility_error, stderr=compatibility_error)
            target_sha256 = hashlib.sha256(target_data).hexdigest()
            guest_target = f"{GUEST_BIN_DIR}/{target_sha256}"
            staged[guest_target] = target_data
            guest_argv[0] = guest_target
            invocation_argv.append({"target_sha256": target_sha256})
            # Remaining argv elements that are local files (e.g. the poc) ride along.
            for i in range(1, len(argv)):
                path = Path(argv[i])
                if path.is_file():
                    guest_path = f"{GUEST_IN_DIR}/{canary}-a{i}"
                    data = path.read_bytes()
                    digest = hashlib.sha256(data).hexdigest()
                    staged[guest_path] = data
                    guest_argv[i] = guest_path
                    invocation_argv.append({"file_sha256": digest})
                    input_files.append(digest)
                else:
                    invocation_argv.append({"literal": argv[i]})
            preload = guest_env.get("LD_PRELOAD", "")
            if preload:
                if not guest_target_supports_preload(target_data):
                    error = "remote LD_PRELOAD proof requires an interpreter-backed target"
                    return ExecResult(error=error, stderr=error)
                parts = re.split(r"([:\s]+)", preload)
                identity_parts = list(parts)
                for index, value in enumerate(parts):
                    if not value or re.fullmatch(r"[:\s]+", value):
                        continue
                    preload_path = Path(value)
                    if not preload_path.is_file():
                        error = f"remote LD_PRELOAD component is not a local file: {value}"
                        return ExecResult(error=error, stderr=error)
                    data = preload_path.read_bytes()
                    digest = hashlib.sha256(data).hexdigest()
                    guest_path = f"{GUEST_IN_DIR}/{canary}-env-{index}-{digest}.so"
                    staged[guest_path] = data
                    parts[index] = guest_path
                    identity_parts[index] = f"sha256:{digest}"
                    env_files.append(digest)
                    receipt_path = preload_path.with_suffix(".build.json")
                    internal_shim = preload_path.name.startswith(
                        ("quarantine_guard.linux-", "exectrap_shim.linux-")
                    )
                    if internal_shim and not receipt_path.is_file():
                        error = f"internal preload shim lacks build receipt: {preload_path}"
                        return ExecResult(error=error, stderr=error)
                    if receipt_path.is_file():
                        receipt_raw = json.loads(receipt_path.read_text())
                        if not isinstance(receipt_raw, dict):
                            error = f"invalid preload build receipt: {receipt_path}"
                            return ExecResult(error=error, stderr=error)
                        compiler_sha = str(receipt_raw.get("compiler_sha256", ""))
                        source_sha = str(receipt_raw.get("source_sha256", ""))
                        if not _SHA256_RE.fullmatch(compiler_sha) or not _SHA256_RE.fullmatch(
                            source_sha
                        ):
                            error = f"invalid preload build receipt: {receipt_path}"
                            return ExecResult(error=error, stderr=error)
                        env_build_receipts.append(
                            {
                                "artifact_sha256": digest,
                                "compiler_sha256": compiler_sha,
                                "source_sha256": source_sha,
                            }
                        )
                guest_env["LD_PRELOAD"] = "".join(parts)
                identity_env["LD_PRELOAD"] = "".join(identity_parts)
        except (OSError, json.JSONDecodeError) as e:
            return ExecResult(error=str(e), stderr=str(e))
        stdin_guest: str | None = None
        if stdin:
            stdin_guest = f"{GUEST_IN_DIR}/{canary}-stdin.bin"
            staged[stdin_guest] = stdin
        sandbox_id = hashlib.sha256(self.sandbox.encode()).hexdigest()[:8]
        run_sandbox = f"0v-{sandbox_id}-{canary}"
        try:
            script = build_run_script(
                sandbox=run_sandbox, image=self.image, guest_argv=guest_argv,
                staged_files=staged, env=guest_env, timeout=timeout, canary=canary,
                stdin_guest_path=stdin_guest, expected_msb_sha256=self.expected_msb_sha256,
            )
            input_identity = json.dumps(
                {
                    "argv_files": input_files,
                    "env_files": env_files,
                    "stdin_sha256": hashlib.sha256(stdin).hexdigest(),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            invocation_identity = json.dumps(
                {
                    "argv": invocation_argv,
                    "env": identity_env,
                    "stdin_sha256": hashlib.sha256(stdin).hexdigest(),
                    "timeout": timeout,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        except (OSError, ValueError, OverflowError) as exc:
            error = f"invalid remote execution request: {exc}"
            return ExecResult(error=error, stderr=error)
        provenance = {
            "executor": "microsandbox-ssh/v2",
            "host": self.host,
            "image": self.image,
            "msb_sha256": self.expected_msb_sha256,
            "sandbox": run_sandbox,
            "target_sha256": target_sha256,
            "input_sha256": hashlib.sha256(input_identity).hexdigest(),
            "invocation_sha256": hashlib.sha256(invocation_identity).hexdigest(),
            "preload_sha256": ",".join(env_files),
            "preload_build_sha256": hashlib.sha256(
                json.dumps(
                    env_build_receipts, sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest(),
            "preload_smoke": "pinned-guest:/bin/true" if env_files else "",
        }
        try:
            p = self._ssh(script, timeout=timeout + SSH_GRACE_S)
        except CancelledError as exc:
            return ExecResult(
                error=str(exc),
                stderr=str(exc),
                provenance=provenance,
                cancelled=True,
            )
        except subprocess.TimeoutExpired:
            error = "infrastructure timeout (ssh/microsandbox produced no verdict)"
            return ExecResult(error=error, stderr=error, provenance=provenance)
        except OSError as e:
            return ExecResult(error=str(e), stderr=str(e), provenance=provenance)
        text = p.stdout.decode("utf-8", "replace")
        if p.returncode != 0:
            detail = p.stderr.decode("utf-8", "replace").strip()
            error = f"ssh transport exited {p.returncode}: {detail[:300]}"
            return ExecResult(
                error=error, stderr=text.strip(), provenance=provenance
            )
        rc, timed_out, output, protocol_error = parse_exec_output(text, canary)
        if rc is None:
            detail = p.stderr.decode("utf-8", "replace").strip()
            error = (
                f"sandbox produced no trusted verdict ({protocol_error}; "
                f"ssh rc={p.returncode}; {detail[:300]}; out: {output[:300]})"
            )
            return ExecResult(
                error=error, stderr=output, provenance=provenance,
            )
        return ExecResult(
            returncode=rc, stderr=output, timed_out=timed_out, stdout="",
            provenance=provenance,
        )


# --- selection ---------------------------------------------------------------


def bind_run_context(executor: Executor, context: RunContext) -> Executor:
    """Return a run-local executor without mutating a shared configured instance."""
    binder = getattr(executor, "for_context", None)
    if callable(binder):
        return binder(context)  # type: ignore[no-any-return]
    return executor


_executor: Executor | None = None


def executor_from_env() -> Executor:
    """Resolve the execution backend from the environment (see module docs)."""
    kind = os.environ.get("ZEROVERSE_EXECUTOR", "").strip().lower()
    if kind in ("msb", "microsandbox"):
        return MsbSshExecutor(
            host=os.environ.get("ZEROVERSE_MSB_HOST", "fuzzer"),
            image=os.environ.get("ZEROVERSE_MSB_IMAGE", DEFAULT_MSB_IMAGE),
            sandbox=os.environ.get("ZEROVERSE_MSB_SANDBOX", "0verse-oracle"),
            expected_msb_sha256=os.environ.get(
                "ZEROVERSE_MSB_SHA256", DEFAULT_MSB_SHA256
            ),
        )
    if kind == "local":
        return LocalExecutor()
    if kind:
        return DisabledExecutor(f"unknown ZEROVERSE_EXECUTOR value: {kind!r}")
    return DisabledExecutor(
        "dynamic execution disabled: set ZEROVERSE_EXECUTOR=msb or explicitly "
        "trust the host with ZEROVERSE_EXECUTOR=local"
    )


def current_executor() -> Executor:
    """The process-wide executor (lazy, env-resolved on first use)."""
    global _executor
    if _executor is None:
        _executor = executor_from_env()
    return _executor


def set_executor(ex: Executor) -> None:
    """Override the executor (tests, programmatic routing)."""
    global _executor
    _executor = ex


def reset_executor() -> None:
    """Drop the override; the next ``current_executor()`` re-reads the env."""
    global _executor
    _executor = None
