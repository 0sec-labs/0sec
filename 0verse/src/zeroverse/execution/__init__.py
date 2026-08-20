"""Versioned target-execution adapters.

The scan spine accepts these adapters explicitly.  Importing this package never
selects a remote host or starts execution.
"""

from .contract import (
    EXECUTION_CONTRACT_VERSION,
    ExecutionBackend,
    ExecutionCapabilities,
    ExecutionEvidence,
    ExecutionRequest,
)
from .local import LocalProcessBackend

__all__ = [
    "EXECUTION_CONTRACT_VERSION",
    "ExecutionBackend",
    "ExecutionCapabilities",
    "ExecutionEvidence",
    "ExecutionRequest",
    "LocalProcessBackend",
]
