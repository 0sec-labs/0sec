from __future__ import annotations

import os
import signal
import sys
import threading
import time
from pathlib import Path

import pytest

from zeroverse import atomic_store
from zeroverse.atomic_store import AtomicObjectStore, atomic_write_bytes, canonical_json_bytes
from zeroverse.cancellation import CancellationToken, CancelledError, RunContext
from zeroverse.process_boundary import call_isolated
from zeroverse.receipts import ReceiptStore, StageIdentity
from zeroverse.sandbox_exec import LocalExecutor


def _identity(input_digest: str = "a" * 64, **overrides: object) -> StageIdentity:
    values: dict[str, object] = {
        "stage": "confirm",
        "stage_schema": "confirm/v1",
        "input_sha256": input_digest,
        "options": {"profile": "confirmation", "limit": 4},
        "engine": {"version": "1", "source": "b" * 64},
        "backend": {"name": "local", "tool": "c" * 64},
        "dependencies": {"decompile": "d" * 64},
    }
    values.update(overrides)
    return StageIdentity(**values)  # type: ignore[arg-type]


def _wait_for(path: Path, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert path.exists()


def _spawn_provider_child(pid_path: str) -> None:
    import subprocess

    child = subprocess.Popen(  # foxguard: ignore[py/no-command-injection]
        [sys.executable, "-c", "import time;time.sleep(30)"]
    )
    Path(pid_path).write_text(str(child.pid))
    time.sleep(30)



@pytest.mark.skipif(sys.platform == "linux",
                    reason="process-group reaping Linux runner namespace (ok on macOS)")
def test_isolated_provider_cancellation_reaps_child(tmp_path: Path) -> None:
    token = CancellationToken()
    context = RunContext(time.monotonic() + 10, token)
    pid_path = tmp_path / "provider-child.pid"
    errors: list[BaseException] = []

    def invoke() -> None:
        try:
            call_isolated(_spawn_provider_child, str(pid_path), context=context)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=invoke)
    thread.start()
    _wait_for(pid_path)
    child_pid = int(pid_path.read_text())
    token.cancel("stop provider")
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], CancelledError)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.02)
    else:
        pytest.fail("isolated provider child remained alive")

@pytest.mark.skipif(sys.platform == "linux",
                    reason="process-group reaping Linux runner namespace (ok on macOS)")
def test_cancelled_local_process_reaps_descendants_without_global_mutation(
    tmp_path: Path,
) -> None:
    token = CancellationToken()
    context = RunContext(time.monotonic() + 10, token)
    executor = LocalExecutor(context)
    child_pid_path = tmp_path / "child.pid"
    before_env = dict(os.environ)
    before_term = signal.getsignal(signal.SIGTERM)
    before_alarm = signal.getsignal(signal.SIGALRM)
    result_box: list[object] = []
    script = (
        "import pathlib,subprocess,sys,time; "
        "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
        "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(30)"
    )

    thread = threading.Thread(
        target=lambda: result_box.append(
            executor.run([sys.executable, "-c", script, str(child_pid_path)], timeout=20)
        )
    )
    thread.start()
    _wait_for(child_pid_path)
    child_pid = int(child_pid_path.read_text())
    token.cancel("test cancellation")
    thread.join(timeout=5)

    assert not thread.is_alive()
    result = result_box[0]
    assert result.cancelled  # type: ignore[union-attr]
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.02)
    else:
        pytest.fail("cancelled subprocess descendant remained alive")
    assert dict(os.environ) == before_env
    assert signal.getsignal(signal.SIGTERM) is before_term
    assert signal.getsignal(signal.SIGALRM) is before_alarm


@pytest.mark.skipif(sys.platform == "linux",
                    reason="process-group reaping Linux runner namespace (ok on macOS)")
def test_concurrent_run_cancellation_is_isolated() -> None:
    cancelled = CancellationToken()
    survivor = CancellationToken()
    first = LocalExecutor(RunContext(time.monotonic() + 5, cancelled))
    second = LocalExecutor(RunContext(time.monotonic() + 5, survivor))
    results: dict[str, object] = {}

    first_thread = threading.Thread(
        target=lambda: results.setdefault(
            "first", first.run([sys.executable, "-c", "import time;time.sleep(10)"])
        )
    )
    second_thread = threading.Thread(
        target=lambda: results.setdefault(
            "second", second.run([sys.executable, "-c", "print('ok')"])
        )
    )
    first_thread.start()
    second_thread.start()
    time.sleep(0.1)
    cancelled.cancel()
    first_thread.join(timeout=3)
    second_thread.join(timeout=3)

    assert results["first"].cancelled  # type: ignore[union-attr]
    assert not results["second"].cancelled  # type: ignore[union-attr]
    assert results["second"].stdout == "ok\n"  # type: ignore[union-attr]
    assert not survivor.cancelled


def test_receipt_round_trip_and_every_identity_dimension_misses(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path)
    identity = _identity()
    receipt = store.write_completed(
        identity,
        {"reproduced": True},
        sidecars={
            "pov-input.bin": b"trigger",
            "replay.json": canonical_json_bytes({"returncode": -11}),
            "stdout.txt": b"stdout",
            "stderr.txt": b"stderr",
            "terminal.json": canonical_json_bytes({"state": "confirmed"}),
            "stages.json": canonical_json_bytes({"confirm": "completed"}),
        },
    )

    assert receipt is not None
    assert store.load(identity) is not None
    variants = [
        _identity(input_digest="1" * 64),
        _identity(options={"profile": "analysis", "limit": 4}),
        _identity(engine={"version": "2", "source": "b" * 64}),
        _identity(backend={"name": "local", "tool": "e" * 64}),
        _identity(dependencies={"decompile": "f" * 64}),
        _identity(stage_schema="confirm/v2"),
    ]
    assert all(store.load(variant) is None for variant in variants)


def test_cancelled_partial_and_corrupt_receipts_are_misses(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path)
    identity = _identity()
    token = CancellationToken()
    token.cancel()

    assert store.write_completed(
        identity,
        {"ok": True},
        context=RunContext(time.monotonic() + 5, token),
    ) is None
    assert store.load(identity) is None

    manifest = store._manifests.object_path(identity.key)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text("{not-json")
    assert store.load(identity) is None


def test_pov_sidecar_hash_tamper_is_rejected(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path)
    identity = _identity()
    receipt = store.write_completed(
        identity,
        {"ok": True},
        sidecars={"pov-input.bin": b"original"},
    )
    assert receipt is not None
    digest = next(
        digest
        for name, digest in (
            (name, __import__("hashlib").sha256(data).hexdigest())
            for name, data in receipt.sidecars.items()
        )
        if name == "pov-input.bin"
    )
    store._blob_path(digest).write_bytes(b"tampered")
    assert store.load(identity) is None


def test_concurrent_same_key_writers_serialize_to_one_valid_object(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path)
    identity = _identity()
    barrier = threading.Barrier(3)
    receipts: list[object] = []

    def writer(value: int) -> None:
        barrier.wait()
        receipts.append(store.write_completed(identity, {"writer": value}))

    threads = [threading.Thread(target=writer, args=(value,)) for value in (1, 2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=3)

    assert len(receipts) == 2
    loaded = store.load(identity)
    assert loaded is not None
    assert loaded.sidecars["payload.json"] in {
        b'{"writer":1}',
        b'{"writer":2}',
    }
    assert receipts[0].sidecars["payload.json"] == loaded.sidecars["payload.json"]  # type: ignore[union-attr]
    assert receipts[1].sidecars["payload.json"] == loaded.sidecars["payload.json"]  # type: ignore[union-attr]


def test_atomic_write_failures_leave_prior_valid_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "cache.json"
    atomic_write_bytes(path, b"old")
    real_replace = Path.replace

    monkeypatch.setattr(
        Path,
        "replace",
        lambda self, target: (_ for _ in ()).throw(OSError("replace")),
    )
    with pytest.raises(OSError, match="replace"):
        atomic_write_bytes(path, b"new")
    assert path.read_bytes() == b"old"

    monkeypatch.setattr(Path, "replace", real_replace)
    monkeypatch.setattr(
        atomic_store,
        "_fsync_directory",
        lambda directory: (_ for _ in ()).throw(OSError("fsync")),
    )
    with pytest.raises(OSError, match="fsync"):
        atomic_write_bytes(path, b"newer")
    assert path.read_bytes() == b"old"


def test_corrupt_and_stale_atomic_cache_are_misses(tmp_path: Path) -> None:
    store = AtomicObjectStore(tmp_path, namespace="cache")
    key = "a" * 64
    store.store(key, {"schema": 1}, validator=lambda value: value.get("schema") == 1)
    assert store.load(key, validator=lambda value: value.get("schema") == 2) is None
    store.object_path(key).write_text("[]")
    assert store.load(key) is None


def test_atomic_store_abort_returns_none_and_preserves_empty_state(tmp_path: Path) -> None:
    store = AtomicObjectStore(tmp_path, namespace="abort-test")
    key = "f" * 64
    result = store.store(key, {"value": 1}, abort=lambda: True)
    assert result is None
    assert store.load(key) is None
