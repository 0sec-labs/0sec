"""Cancellable process boundary for otherwise uninterruptible providers."""

from __future__ import annotations

import contextlib
import multiprocessing
import os
import signal
from collections.abc import Callable
from multiprocessing.connection import Connection
from typing import Any, TypeVar

from .cancellation import CancelledError, RunContext

T = TypeVar("T")


class IsolatedCallError(RuntimeError):
    """An isolated provider failed before producing a serializable result."""


def _worker(
    connection: Connection,
    function: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> None:
    try:
        if os.name == "posix":
            os.setsid()
        connection.send(("ready",))
        value = function(*args, **kwargs)
        connection.send(("ok", value))
    except BaseException as exc:
        with contextlib.suppress(BaseException):
            connection.send(("error", type(exc).__name__, str(exc)))
    finally:
        connection.close()


def _stop(process: multiprocessing.Process, grace: float = 0.25) -> None:
    if not process.is_alive():
        process.join(timeout=1.0)
        return

    def signal_process_group(signum: int) -> None:
        if os.name == "posix" and process.pid is not None:
            try:
                os.killpg(process.pid, signum)
                return
            except ProcessLookupError:
                pass
        if signum == signal.SIGTERM:
            process.terminate()
        else:
            process.kill()

    signal_process_group(signal.SIGTERM)
    process.join(timeout=grace)
    if process.is_alive():
        signal_process_group(signal.SIGKILL)
        process.join(timeout=1.0)


def call_isolated(
    function: Callable[..., T],
    *args: Any,
    context: RunContext,
    poll_interval: float = 0.05,
    **kwargs: Any,
) -> T:
    """Execute a provider in a child process and reap its entire process group."""
    context.checkpoint()
    method = "fork" if "fork" in multiprocessing.get_all_start_methods() else "spawn"
    mp: Any = multiprocessing.get_context(method)
    parent, child = mp.Pipe(duplex=False)
    process = mp.Process(target=_worker, args=(child, function, args, kwargs))
    process.daemon = False
    process.start()
    child.close()
    try:
        while True:
            if context.stopped:
                _stop(process)
                raise CancelledError(context.reason)
            if parent.poll(min(poll_interval, max(0.001, context.remaining_seconds()))):
                try:
                    message = parent.recv()
                except EOFError as exc:
                    raise IsolatedCallError("isolated provider closed without a result") from exc
                if not isinstance(message, tuple) or not message:
                    raise IsolatedCallError("isolated provider returned an invalid message")
                if message[0] == "ready":
                    continue
                process.join(timeout=1.0)
                if process.is_alive():
                    _stop(process)
                if message[0] == "ok" and len(message) == 2:
                    return message[1]  # type: ignore[no-any-return]
                if message[0] == "error" and len(message) == 3:
                    raise IsolatedCallError(f"{message[1]}: {message[2]}")
                raise IsolatedCallError("isolated provider returned an invalid message")
            if not process.is_alive():
                process.join(timeout=1.0)
                if parent.poll():
                    continue
                raise IsolatedCallError(
                    f"isolated provider exited {process.exitcode} without a result"
                )
    finally:
        parent.close()
        if process.is_alive():
            _stop(process)
