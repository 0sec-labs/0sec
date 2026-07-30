#!/usr/bin/env bash
#
# Hand a build artifact between CI jobs over the runner host's filesystem.
#
# WHY THIS EXISTS
# ---------------
# Every self-hosted runner in this org lives on one host (colossus, 6
# instances), so a job and its downstream consumers always share a filesystem.
# actions/upload-artifact sent a 2 MB tarball to GitHub's storage so it could
# travel between two processes on the same machine, and that storage is a
# 500 MB org-wide allowance on the GitHub Free plan. It filled up, and from
# 2026-07-27 the upload step failed with "Artifact storage quota has been hit",
# which skipped the docker publish job chained behind it — so a green engine
# build could not produce an image for three days.
#
# actions/cache is not the alternative: same GitHub storage, different quota,
# and this org is already at the 10 GB per-repo cache cap.
#
# TRADE-OFF
# ---------
# This couples CI to a single-runner-host topology. Add a second host to the
# pool and a consumer may land somewhere the file is not. That is why `get`
# fails loudly with an explanatory message rather than continuing with an empty
# directory: the failure mode has to be a red run with a readable reason, not a
# downstream test mysteriously exercising a stale or absent tarball. The fix at
# that point is a real object store (MinIO on vega, or the Hetzner storage-box),
# not a return to upload-artifact.
#
# USAGE
#   ci-artifact-share.sh put <dir>   # publish <dir>/pwnkit-cli-*.tgz
#   ci-artifact-share.sh get <dir>   # place the tarball into <dir>
#   ci-artifact-share.sh clean       # drop this run's share dir
set -euo pipefail

MODE="${1:-}"
DIR="${2:-dist}"

# Overridable so a future multi-host setup can point this at a shared mount
# without editing every workflow.
SHARE_ROOT="${PWNKIT_CI_SHARE_ROOT:-/home/runner/_ci-share}"
RUN_ID="${GITHUB_RUN_ID:-local}"
RUN_ATTEMPT="${GITHUB_RUN_ATTEMPT:-1}"
SHARE_DIR="$SHARE_ROOT/$RUN_ID-$RUN_ATTEMPT"

case "$MODE" in
  put)
    mkdir -p "$SHARE_DIR"
    # Age-based sweep of abandoned dirs. Cancelled and failed runs never reach
    # the clean job, so without this the share root grows without bound on a
    # long-lived runner host. 1 day is far longer than any run here (the whole
    # suite times out at 25 min/job) and short enough to stay small.
    find "$SHARE_ROOT" -mindepth 1 -maxdepth 1 -type d -mtime +1 \
      -exec rm -rf {} + 2>/dev/null || true

    shopt -s nullglob
    files=("$DIR"/pwnkit-cli-*.tgz)
    shopt -u nullglob
    if [[ ${#files[@]} -eq 0 ]]; then
      echo "ERROR: no pwnkit-cli-*.tgz in '$DIR' to stage." >&2
      echo "The pack step should have produced one; failing rather than" >&2
      echo "publishing an empty handoff that downstream jobs would misread." >&2
      exit 1
    fi
    cp -f "${files[@]}" "$SHARE_DIR/"
    echo "staged ${#files[@]} file(s) in $SHARE_DIR:"
    ls -la "$SHARE_DIR"
    ;;

  get)
    if [[ ! -d "$SHARE_DIR" ]]; then
      cat >&2 <<EOF
ERROR: shared artifact dir '$SHARE_DIR' does not exist.

This job expected the build job to have staged the CLI tarball on THIS host.
The handoff is filesystem-local by design (see the header of this script), so
the usual cause is that the pool now spans more than one runner host and this
job landed on a different one from the build.

Fix: move the handoff to a real object store (MinIO on vega, or the Hetzner
storage-box) and point PWNKIT_CI_SHARE_ROOT at a shared mount. Do NOT go back
to actions/upload-artifact — the org's GitHub storage allowance is what this
replaced.
EOF
      exit 1
    fi
    shopt -s nullglob
    files=("$SHARE_DIR"/pwnkit-cli-*.tgz)
    shopt -u nullglob
    if [[ ${#files[@]} -eq 0 ]]; then
      echo "ERROR: '$SHARE_DIR' exists but holds no pwnkit-cli-*.tgz." >&2
      exit 1
    fi
    mkdir -p "$DIR"
    cp -f "${files[@]}" "$DIR/"
    echo "fetched ${#files[@]} file(s) into $DIR:"
    ls -la "$DIR"/pwnkit-cli-*.tgz
    ;;

  clean)
    rm -rf "$SHARE_DIR"
    echo "removed $SHARE_DIR"
    ;;

  *)
    echo "usage: $0 {put|get|clean} [dir]" >&2
    exit 2
    ;;
esac
