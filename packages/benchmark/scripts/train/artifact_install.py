"""Install exactly the bytes authorized by the evolution registry bridge."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

BRIDGE = Path(__file__).with_name("artifact-bridge.mjs")


def install_authorized_artifact(
    store: Path, version: str, candidate: Path, artifact: str, kind: str, destination: Path
) -> str:
    """Reject stale bytes and publish atomically; failed authorization never writes destination."""
    try:
        result = subprocess.run(
            ["node", str(BRIDGE), "authorize", str(store), version, str(candidate), artifact, kind],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            raise ValueError((result.stdout + result.stderr).strip() or "authorization failed")
        receipt = json.loads(result.stdout)
        if not isinstance(receipt, dict) or receipt.get("authorized") is not True or receipt.get("versionId") != version:
            raise ValueError("authorization bridge returned an invalid version receipt")
        expected = receipt.get("fileDigest")
        if not isinstance(expected, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", expected) is None:
            raise ValueError("authorization bridge omitted a valid artifact digest")
        fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 512 * 1024 * 1024:
                raise ValueError("candidate must be a bounded regular file without aliases")
            content = source.read(info.st_size + 1)
        if "sha256:" + hashlib.sha256(content).hexdigest() != expected:
            raise ValueError("candidate bytes changed after evolution authorization")

        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(prefix=".0sec-install-", dir=destination.parent, delete=False) as output:
                temporary = Path(output.name)
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination)
            temporary = None
            directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return expected
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Evolution artifact installation failed: {error}", file=sys.stderr)
        raise SystemExit(3) from error
