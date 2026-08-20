"""PoV emitter — the standalone pwntools replay script (no execution here)."""

from pathlib import Path

from zeroverse.poc import emit_pov_script, write_pov_script
from zeroverse.report import PoV


def test_emit_embeds_vector_and_expectation() -> None:
    pov = PoV(input_bytes=b"AAAA", crash_class="SIGSEGV", reproduced=True)
    script = emit_pov_script("/tmp/vuln", pov, script_name="pov.py")
    assert "BINARY = '/tmp/vuln'" in script
    assert b"AAAA".hex() in script          # crashing bytes embedded
    assert "EXPECT = 'SIGSEGV'" in script
    assert "from pwn import" in script       # depends only on pwntools
    assert "zeroverse" not in script         # self-contained


def test_emit_carries_guard_env() -> None:
    # A silent heap bug only reproduces under the guard allocator env.
    pov = PoV(input_bytes=b"A" * 40, env={"LD_PRELOAD": "/lib/libefence.so.0"},
              crash_class="SIGSEGV", reproduced=True)
    script = emit_pov_script("/tmp/heap", pov)
    assert "libefence.so.0" in script


def test_write_pov_script_is_executable(tmp_path: Path) -> None:
    pov = PoV(input_bytes=b"x", crash_class="SIGSEGV", reproduced=True)
    out = write_pov_script(tmp_path / "pov.py", "/tmp/vuln", pov)
    assert out.exists() and out.stat().st_mode & 0o111   # +x bit set
    assert out.read_text().startswith("#!/usr/bin/env python3")
