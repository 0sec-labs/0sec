#!/usr/bin/env bash
# Build the OPTIONAL 0verse native fast-path (zeroverse._native) and install the
# compiled module into the active environment's ``zeroverse`` package.
#
# 0verse runs fine WITHOUT this — it only speeds up large-input ingest + lens
# scanning. Requires a Rust toolchain (rustc/cargo) and ``pip install maturin``.
#
#   ./rust/build.sh            # build + drop the .so next to the installed package
#
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

command -v cargo >/dev/null || { echo "cargo (Rust toolchain) not found"; exit 1; }
command -v maturin >/dev/null || { echo "maturin not found — pip install maturin"; exit 1; }

# Build from the crate dir so maturin picks up Cargo.toml + pyproject.toml here.
( cd "$HERE" && maturin build --release )
WHEEL="$(ls -t "$HERE"/target/wheels/*.whl | head -1)"
echo "built: $WHEEL"

# Locate the installed zeroverse package (editable src layout or site-packages).
DEST="$(python - <<'PY'
import importlib.util, pathlib, sys
spec = importlib.util.find_spec("zeroverse")
assert spec and spec.origin, "zeroverse package not importable; install it first"
print(pathlib.Path(spec.origin).parent)
PY
)"

# The wheel ships ``_native/_native.abi3.so``; drop that .so into the package dir
# so it imports as ``zeroverse._native``.
TMP="$(mktemp -d)"
unzip -o -q "$WHEEL" -d "$TMP"
SO="$(find "$TMP" -name '_native*.so' | head -1)"
cp "$SO" "$DEST/"
rm -rf "$TMP"
echo "installed: $DEST/$(basename "$SO")"
python -c "from zeroverse import _native; print('native backend:', _native.backend())"
