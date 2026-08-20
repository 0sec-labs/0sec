"""Hard-process-bound acquisition for one exact retained AFD CFG/SSA side."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, cast

from .windows_afd_handler_cfg_ssa_ghidra import acquire_afd_handler_cfg_ssa_side
from .windows_afd_handler_semantics import _validate as _validate_native


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 6 or args[4] not in {"side_a", "side_b"}:
        return 2
    binary, pdb, home, native_path, side, output_path = map(Path, args)
    native = _validate_native(json.loads(native_path.read_bytes()))
    native_side = cast(dict[str, Any], cast(dict[str, object], native["sides"])[str(side)])
    facts = acquire_afd_handler_cfg_ssa_side(binary, pdb, home, native_side, side=str(side))
    raw = json.dumps(facts, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(output_path, flags, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("AFD CFG/SSA side output write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    result = {
        "schema_version": "0verse.windows-afd-cfg-ssa-side-isolated-result/v1",
        "side": str(side),
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
    }
    print("0VERSE_AFD_CFG_SSA_SIDE_RESULT=" + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
