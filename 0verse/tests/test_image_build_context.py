from __future__ import annotations

import shlex
import tomllib
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).parents[1]


def test_dockerfile_copies_every_forced_wheel_include() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    forced = project["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    copied_sources = _docker_copy_sources((ROOT / "Dockerfile").read_text())

    missing = [
        source
        for source in forced
        if not any(_contains(copied, source) for copied in copied_sources)
    ]
    assert missing == [], f"Docker build context omits forced wheel includes: {missing}"


def _docker_copy_sources(dockerfile: str) -> list[str]:
    sources: list[str] = []
    for raw_line in dockerfile.splitlines():
        line = raw_line.strip()
        if not line.startswith("COPY "):
            continue
        fields = shlex.split(line)
        sources.extend(field for field in fields[1:-1] if not field.startswith("--"))
    return sources


def _contains(copied: str, required: str) -> bool:
    copied_path = PurePosixPath(copied)
    required_path = PurePosixPath(required)
    return copied_path == PurePosixPath(".") or required_path.is_relative_to(copied_path)
