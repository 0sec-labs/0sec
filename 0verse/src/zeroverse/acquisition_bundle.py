"""Fail-closed filesystem intake for AcquisitionManifest v1 bundles.

The manifest is evidence about an acquisition. This module verifies that the
directory supplied to an offline consumer still matches that evidence without
upgrading recorded claims or making unavailable bytes appear present.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from .acquisition import AcquisitionArtifact, AcquisitionManifest, load_acquisition_manifest

ACQUISITION_BUNDLE_MANIFEST = "acquisition.json"

BundleIssueCode = Literal[
    "artifact-changed-during-read",
    "artifact-missing",
    "artifact-path-alias",
    "artifact-path-component",
    "artifact-path-symlink",
    "artifact-path-type",
    "artifact-read-failed",
    "artifact-reserved-path",
    "artifact-sha256-mismatch",
    "artifact-size-mismatch",
    "artifact-unexpected",
    "bundle-invalid",
    "manifest-invalid",
]


@dataclass(frozen=True)
class BundleValidationIssue:
    """One stable, machine-addressable acquisition bundle failure."""

    code: BundleIssueCode
    path: str
    detail: str
    artifact_id: str | None = None

    def __str__(self) -> str:
        subject = (
            f"artifact {self.artifact_id!r} at {self.path!r}"
            if self.artifact_id is not None
            else repr(self.path)
        )
        return f"[{self.code}] {subject}: {self.detail}"


class AcquisitionBundleValidationError(ValueError):
    """Raised with every deterministic issue found in one bundle validation."""

    def __init__(self, issues: Iterable[BundleValidationIssue]) -> None:
        self.issues = tuple(
            sorted(
                issues,
                key=lambda issue: (
                    issue.path,
                    issue.artifact_id or "",
                    issue.code,
                    issue.detail,
                ),
            )
        )
        if not self.issues:
            raise ValueError("acquisition bundle validation error requires at least one issue")
        rendered = "; ".join(str(issue) for issue in self.issues)
        super().__init__(
            f"acquisition bundle validation failed with {len(self.issues)} issue(s): {rendered}"
        )


@dataclass(frozen=True)
class ValidatedAcquisitionArtifact:
    """A declared artifact and the identity observed at bundle load time."""

    artifact: AcquisitionArtifact
    path: Path
    observed_size: int | None
    observed_sha256: str | None

    @property
    def is_present(self) -> bool:
        return self.observed_size is not None


@dataclass(frozen=True)
class AcquisitionBundle:
    """A manifest and artifact paths verified beneath one canonical root."""

    root: Path
    manifest_path: Path
    manifest: AcquisitionManifest
    artifacts: tuple[ValidatedAcquisitionArtifact, ...]

    def artifact(self, artifact_id: str) -> ValidatedAcquisitionArtifact:
        for artifact in self.artifacts:
            if artifact.artifact.artifact_id == artifact_id:
                return artifact
        raise KeyError(artifact_id)

    def analysis_artifacts(self) -> tuple[ValidatedAcquisitionArtifact, ...]:
        eligible_ids = {item.artifact_id for item in self.manifest.analysis_inputs()}
        return tuple(
            artifact
            for artifact in self.artifacts
            if artifact.artifact.artifact_id in eligible_ids and artifact.is_present
        )


@dataclass(frozen=True)
class _ObservedFile:
    size: int
    sha256: str
    identity: tuple[int, int]


class _ArtifactReadError(Exception):
    def __init__(self, code: BundleIssueCode, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _artifact_issue(
    artifact: AcquisitionArtifact, code: BundleIssueCode, detail: str
) -> BundleValidationIssue:
    return BundleValidationIssue(
        code=code,
        artifact_id=artifact.artifact_id,
        path=artifact.path,
        detail=detail,
    )


def _inspect_artifact_path(
    root: Path, artifact: AcquisitionArtifact
) -> tuple[Path, bool, BundleValidationIssue | None]:
    parts = PurePosixPath(artifact.path).parts
    candidate = root.joinpath(*parts)
    current = root
    for index, part in enumerate(parts):
        current /= part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            return candidate, False, None
        except OSError as exc:
            return (
                candidate,
                False,
                _artifact_issue(
                    artifact,
                    "artifact-read-failed",
                    f"could not inspect the path (errno={exc.errno})",
                ),
            )
        if stat.S_ISLNK(metadata.st_mode):
            return (
                candidate,
                False,
                _artifact_issue(
                    artifact,
                    "artifact-path-symlink",
                    f"path component {part!r} is a symlink",
                ),
            )
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            return (
                candidate,
                False,
                _artifact_issue(
                    artifact,
                    "artifact-path-component",
                    f"path component {part!r} is not a directory",
                ),
            )
        if index == len(parts) - 1 and not stat.S_ISREG(metadata.st_mode):
            return (
                candidate,
                False,
                _artifact_issue(
                    artifact,
                    "artifact-path-type",
                    "declared artifact path is not a regular file",
                ),
            )
    return candidate, True, None


def _hash_regular_file(path: Path) -> _ObservedFile:
    try:
        path_before = os.lstat(path)
    except OSError as exc:
        raise _ArtifactReadError(
            "artifact-changed-during-read", f"path disappeared before opening (errno={exc.errno})"
        ) from exc
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _ArtifactReadError(
            "artifact-read-failed", f"could not open the artifact (errno={exc.errno})"
        ) from exc

    digest = hashlib.sha256()
    count = 0
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(path_before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or (path_before.st_dev, path_before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise _ArtifactReadError(
                "artifact-changed-during-read", "path identity changed while it was opened"
            )
        try:
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                count += len(chunk)
                digest.update(chunk)
        except OSError as exc:
            raise _ArtifactReadError(
                "artifact-read-failed", f"could not read the artifact (errno={exc.errno})"
            ) from exc

        after = os.fstat(descriptor)
        try:
            path_after = os.lstat(path)
        except OSError as exc:
            raise _ArtifactReadError(
                "artifact-changed-during-read",
                f"path disappeared while it was read (errno={exc.errno})",
            ) from exc
        if (
            count != opened.st_size
            or _stat_identity(after) != _stat_identity(opened)
            or not stat.S_ISREG(path_after.st_mode)
            or (path_after.st_dev, path_after.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise _ArtifactReadError(
                "artifact-changed-during-read", "artifact bytes or path identity changed while read"
            )
        return _ObservedFile(
            size=count,
            sha256=digest.hexdigest(),
            identity=(after.st_dev, after.st_ino),
        )
    finally:
        os.close(descriptor)


def _expected_identity(artifact: AcquisitionArtifact) -> tuple[int, str]:
    if artifact.integrity == "modified":
        if artifact.observed_size is None or artifact.observed_sha256 is None:
            raise AssertionError("modified artifact lacks its observed identity")
        return artifact.observed_size, artifact.observed_sha256
    if artifact.size is None or artifact.sha256 is None:
        raise AssertionError("present artifact lacks its declared identity")
    return artifact.size, artifact.sha256


def _validate_artifact(
    root: Path, artifact: AcquisitionArtifact
) -> tuple[
    ValidatedAcquisitionArtifact | None,
    tuple[BundleValidationIssue, ...],
    _ObservedFile | None,
]:
    if artifact.path == ACQUISITION_BUNDLE_MANIFEST:
        issue = _artifact_issue(
            artifact,
            "artifact-reserved-path",
            "the bundle manifest cannot also be an acquisition artifact",
        )
        return None, (issue,), None

    path, exists, path_issue = _inspect_artifact_path(root, artifact)
    if path_issue is not None:
        return None, (path_issue,), None
    if artifact.availability == "missing":
        if exists:
            issue = _artifact_issue(
                artifact,
                "artifact-unexpected",
                "manifest declares the artifact missing but the path exists",
            )
            return None, (issue,), None
        return (
            ValidatedAcquisitionArtifact(
                artifact=artifact,
                path=path,
                observed_size=None,
                observed_sha256=None,
            ),
            (),
            None,
        )
    if not exists:
        issue = _artifact_issue(
            artifact,
            "artifact-missing",
            "manifest declares the artifact present but the path is absent",
        )
        return None, (issue,), None

    try:
        observed = _hash_regular_file(path)
    except _ArtifactReadError as exc:
        return None, (_artifact_issue(artifact, exc.code, exc.detail),), None

    expected_size, expected_sha256 = _expected_identity(artifact)
    issues: list[BundleValidationIssue] = []
    identity_label = (
        "observed modified identity" if artifact.integrity == "modified" else "declaration"
    )
    if observed.size != expected_size:
        issues.append(
            _artifact_issue(
                artifact,
                "artifact-size-mismatch",
                f"{identity_label} expects {expected_size} byte(s), found {observed.size}",
            )
        )
    if observed.sha256 != expected_sha256:
        issues.append(
            _artifact_issue(
                artifact,
                "artifact-sha256-mismatch",
                f"{identity_label} expects {expected_sha256}, found {observed.sha256}",
            )
        )
    validated = ValidatedAcquisitionArtifact(
        artifact=artifact,
        path=path,
        observed_size=observed.size,
        observed_sha256=observed.sha256,
    )
    return validated, tuple(issues), observed


def _canonical_bundle_root(path: str | Path) -> Path:
    requested = Path(path)
    try:
        metadata = os.lstat(requested)
    except OSError as exc:
        raise AcquisitionBundleValidationError(
            [
                BundleValidationIssue(
                    code="bundle-invalid",
                    path=str(requested),
                    detail=f"bundle root does not exist or is unreadable (errno={exc.errno})",
                )
            ]
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise AcquisitionBundleValidationError(
            [
                BundleValidationIssue(
                    code="bundle-invalid",
                    path=str(requested),
                    detail="bundle root must be a directory and not a symlink",
                )
            ]
        )
    try:
        return requested.resolve(strict=True)
    except OSError as exc:
        raise AcquisitionBundleValidationError(
            [
                BundleValidationIssue(
                    code="bundle-invalid",
                    path=str(requested),
                    detail=f"bundle root could not be resolved (errno={exc.errno})",
                )
            ]
        ) from exc


def load_acquisition_bundle(path: str | Path) -> AcquisitionBundle:
    """Load and verify an ``acquisition.json`` bundle without hardware access.

    Missing and explicitly modified artifacts are valid evidence states when the
    filesystem agrees with the manifest. Any contradiction raises one error that
    carries all issues sorted independently of manifest artifact order.
    """

    root = _canonical_bundle_root(path)
    manifest_path = root / ACQUISITION_BUNDLE_MANIFEST
    try:
        manifest = load_acquisition_manifest(manifest_path)
    except ValueError as exc:
        raise AcquisitionBundleValidationError(
            [
                BundleValidationIssue(
                    code="manifest-invalid",
                    path=ACQUISITION_BUNDLE_MANIFEST,
                    detail=str(exc),
                )
            ]
        ) from exc

    issues: list[BundleValidationIssue] = []
    by_id: dict[str, ValidatedAcquisitionArtifact] = {}
    physical_paths: dict[tuple[int, int], AcquisitionArtifact] = {}
    for artifact in sorted(manifest.artifacts, key=lambda item: (item.path, item.artifact_id)):
        validated, artifact_issues, observed = _validate_artifact(root, artifact)
        issues.extend(artifact_issues)
        if validated is not None:
            by_id[artifact.artifact_id] = validated
        if observed is None or observed.identity[1] == 0:
            continue
        aliased = physical_paths.get(observed.identity)
        if aliased is not None:
            issues.append(
                _artifact_issue(
                    artifact,
                    "artifact-path-alias",
                    f"path names the same regular file as {aliased.path!r}",
                )
            )
        else:
            physical_paths[observed.identity] = artifact

    if issues:
        raise AcquisitionBundleValidationError(issues)
    return AcquisitionBundle(
        root=root,
        manifest_path=manifest_path,
        manifest=manifest,
        artifacts=tuple(by_id[artifact.artifact_id] for artifact in manifest.artifacts),
    )
