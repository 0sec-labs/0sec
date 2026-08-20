"""Fresh-process full replay for one private AFD native-evidence bundle."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from .windows_afd_handler_semantics import (
    _verify_snapshotted_semantics_bundle,
    canonical_handler_semantics_bytes,
)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        return 2
    print("0VERSE_AFD_ISOLATED_PHASE=full-replay-start", flush=True)
    artifact = _verify_snapshotted_semantics_bundle(Path(args[0]), Path(args[1]))
    result = {
        "schema_version": "0verse.windows-afd-isolated-replay-result/v1",
        "phase": "full-replay-complete",
        "artifact_sha256": hashlib.sha256(
            canonical_handler_semantics_bytes(artifact)
        ).hexdigest(),
    }
    print("0VERSE_AFD_ISOLATED_RESULT=" + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
