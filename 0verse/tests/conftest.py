"""Explicitly authorize trusted local fixture execution in the test harness."""

from __future__ import annotations

import os

os.environ.setdefault("ZEROVERSE_EXECUTOR", "local")
