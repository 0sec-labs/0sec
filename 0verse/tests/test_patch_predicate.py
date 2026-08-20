"""Tests for the patch-predicate oracle.

Two layers, matching the module's discipline:
  * pure-logic (no compiler, no network): the LLM extraction is MOCKED, and we
    check the mechanical parts — predicate parsing, sink-line resolution against the
    vulnerable source, probe construction, honest fallthrough for algorithmic
    rewrites, and GDB-output parsing.
  * real mechanical confirm: inside an already-established container, compile a TOY
    -g binary with a single guarded sink and prove ``confirm`` gives the objective
    benign-vs-trigger verdict via a live GDB conditional breakpoint. Never run an
    untrusted test target directly on the orchestrator host.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

from zeroverse import patch_predicate as pp

HAVE_GCC = shutil.which("gcc") is not None
HAVE_GDB = shutil.which("gdb") is not None
HAVE_CONTAINED_GDB = (
    HAVE_GCC
    and HAVE_GDB
    and Path("/.dockerenv").exists()
    and os.environ.get("ZEROVERSE_TEST_SANDBOX_NETWORK") == "none"
    and os.environ.get("ZEROVERSE_TEST_SANDBOX_LIMITS") == "enforced"
)


def _start_contained_test_gdb(argv: list[str]) -> subprocess.Popen[bytes]:
    # Test-only: the caller verifies the bounded outer container before reaching
    # this structured argv, shell=False launch. Production exposes no host runner.
    p = subprocess.Popen(  # foxguard: ignore[py/taint-command-injection,py/no-command-injection]
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    return p  # noqa: RET504 - keep the Foxguard suppression on the exact sink line


class _FakeSandbox:
    def __init__(
        self,
        *,
        mi_output: bytes = b"",
        returncode: int | None = 0,
        timed_out: bool = False,
        process_tree_terminated: bool = False,
        isolation: str = "vm",
        network_disabled: bool = True,
        resource_limits_enforced: bool = True,
        output_limit_enforced: bool = True,
        target_digest_verified: bool = True,
        input_digest_verified: bool = True,
        error: str = "",
    ) -> None:
        self.mi_output = mi_output
        self.returncode = returncode
        self.timed_out = timed_out
        self.process_tree_terminated = process_tree_terminated
        self.isolation = isolation
        self.network_disabled = network_disabled
        self.resource_limits_enforced = resource_limits_enforced
        self.output_limit_enforced = output_limit_enforced
        self.target_digest_verified = target_digest_verified
        self.input_digest_verified = input_digest_verified
        self.error = error
        self.requests: list[pp.PredicateSandboxRequest] = []

    def run(self, request: pp.PredicateSandboxRequest) -> pp.PredicateSandboxResult:
        self.requests.append(request)
        return pp.PredicateSandboxResult(
            isolation=self.isolation,
            target_sha256=request.target_sha256,
            input_sha256=request.input_sha256,
            mi_output=self.mi_output,
            returncode=self.returncode,
            timed_out=self.timed_out,
            process_tree_terminated=self.process_tree_terminated,
            network_disabled=self.network_disabled,
            resource_limits_enforced=self.resource_limits_enforced,
            output_limit_enforced=self.output_limit_enforced,
            target_digest_verified=self.target_digest_verified,
            input_digest_verified=self.input_digest_verified,
            error=self.error,
        )


class _ContainedGdbTestSandbox:
    """Live-test boundary; enabled only when pytest itself runs in a container."""

    def run(self, request: pp.PredicateSandboxRequest) -> pp.PredicateSandboxResult:
        if not Path("/.dockerenv").exists():
            raise RuntimeError("live predicate test requires an outer container")
        if os.environ.get("ZEROVERSE_TEST_SANDBOX_NETWORK") != "none":
            raise RuntimeError("live predicate test requires network-disabled containment")
        if os.environ.get("ZEROVERSE_TEST_SANDBOX_LIMITS") != "enforced":
            raise RuntimeError("live predicate test requires bounded container resources")
        if pp._sha256_file(request.binary) != request.target_sha256:
            raise RuntimeError("staged target digest mismatch")
        if hashlib.sha256(request.candidate_input).hexdigest() != request.input_sha256:
            raise RuntimeError("staged input digest mismatch")
        debugger = shutil.which("gdb")
        if debugger is None:
            raise RuntimeError("gdb unavailable in test container")
        with tempfile.TemporaryDirectory() as directory:
            run_argv = list(request.extra_argv)
            if request.vector == "file":
                candidate = Path(directory) / "input.bin"
                candidate.write_bytes(request.candidate_input)
                run_argv.insert(0, str(candidate))
            else:
                run_argv.insert(0, request.candidate_input.decode("utf-8", "strict"))
            inferior_output = Path(directory) / "inferior-output.txt"
            inferior_output.touch(mode=0o600)
            probe = pp.InstrumentedProbe(
                binary=request.binary,
                bp_spec=request.bp_spec,
                condition=request.condition,
                controlled_vars=list(request.controlled_vars),
                source_file=request.source_file,
                mechanically_bound=request.mechanically_bound,
                binding_digest_sha256=request.binding_digest_sha256,
            )
            argv = probe.gdb_argv(run_argv, debugger=debugger)
            process = _start_contained_test_gdb(argv)
            try:
                stdout, stderr = process.communicate(
                    input=probe.mi_commands(str(inferior_output)),
                    timeout=request.timeout,
                )
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                return pp.PredicateSandboxResult(
                    isolation="container",
                    target_sha256=request.target_sha256,
                    input_sha256=request.input_sha256,
                    timed_out=True,
                    process_tree_terminated=True,
                    network_disabled=True,
                    resource_limits_enforced=True,
                    output_limit_enforced=True,
                    target_digest_verified=True,
                    input_digest_verified=True,
                )
            return pp.PredicateSandboxResult(
                isolation="container",
                target_sha256=request.target_sha256,
                input_sha256=request.input_sha256,
                mi_output=stdout,
                debugger_stderr=stderr,
                inferior_output=inferior_output.read_bytes(),
                returncode=process.returncode,
                network_disabled=True,
                resource_limits_enforced=True,
                output_limit_enforced=True,
                target_digest_verified=True,
                input_digest_verified=True,
            )


CONTAINED_GDB = _ContainedGdbTestSandbox()


# --- a mock LLM: returns a fixed structured predicate ----------------------

class _GuardLLM:
    """Mock that returns a single-guard predicate (the tractable shape)."""

    def __init__(self, **overrides):
        self.payload = {
            "single_guard": True,
            "file": "foo.c",
            "function": "copy_it",
            "condition_expr": "len >= max",
            "controlled_vars": ["len", "max"],
            "anchor_hint": "dst[len] = src[len];",
            "kind": "bounds",
            "confidence": 0.9,
            "note": "",
        }
        self.payload.update(overrides)

    def complete_json(self, system, prompt, schema):
        return dict(self.payload)


class _RewriteLLM:
    """Mock for an algorithmic rewrite — no localizable single guard."""

    def complete_json(self, system, prompt, schema):
        return {
            "single_guard": False,
            "condition_expr": "",
            "anchor_hint": "",
            "note": "fix restructures the whole parse loop; no single guard",
        }


VULN_SRC = textwrap.dedent(
    """\
    void copy_it(char *dst, char *src, int len, int max) {
        int i = 0;
        while (len > 0) {
            dst[len] = src[len];
            len--;
        }
    }
    """
)


# --- predicate extraction + line resolution --------------------------------

def test_extract_single_guard_resolves_sink_line():
    pred = pp.extract_predicate("<diff>", VULN_SRC, _GuardLLM())
    assert pred.single_guard
    assert pred.condition_expr == "len >= max"
    assert pred.controlled_vars == ["len", "max"]
    # the sink line is resolved against the VULNERABLE source, not the diff
    assert pred.line_anchor == 4  # `dst[len] = src[len];`
    assert pred.localizable
    assert pred.trigger_value is True
    assert not pred.mechanically_bound
    assert not pred.binding_digest_sha256


def test_extract_exact_added_guard_is_mechanically_bound():
    diff = "@@ -1,2 +1,3 @@\n+    if (len >= max) return;\n"
    pred = pp.extract_predicate(diff, VULN_SRC, _GuardLLM())
    assert pred.localizable
    assert pred.mechanically_bound
    assert len(pred.binding_digest_sha256) == 64


def test_extract_duplicate_added_guard_is_not_mechanically_bound():
    diff = "+    if (len >= max) return;\n+    if (len >= max) return;\n"
    pred = pp.extract_predicate(diff, VULN_SRC, _GuardLLM())
    assert pred.localizable
    assert not pred.mechanically_bound


def test_extract_unbound_constant_remains_observation_only():
    pred = pp.extract_predicate(
        "+    if (len >= max) return;",
        VULN_SRC,
        _GuardLLM(condition_expr="1", confidence=0.0),
    )
    assert pred.localizable
    assert not pred.mechanically_bound
    assert "non-authoritative" in pred.note


def test_extract_algorithmic_rewrite_abstains():
    pred = pp.extract_predicate("<diff>", VULN_SRC, _RewriteLLM())
    assert pred.single_guard is False
    assert pred.localizable is False
    assert "no single guard" in pred.note or "no localizable" in pred.note


def test_extract_unmatchable_anchor_is_not_localizable():
    pred = pp.extract_predicate(
        "<diff>", VULN_SRC, _GuardLLM(anchor_hint="this text is not in the source")
    )
    assert pred.single_guard
    assert pred.line_anchor is None
    assert not pred.localizable
    assert "cannot localize" in pred.note


def test_extract_ambiguous_anchor_abstains():
    source = VULN_SRC + "\nvoid other(void) { dst[len] = src[len]; }\n"
    pred = pp.extract_predicate("<diff>", source, _GuardLLM())
    assert not pred.localizable
    assert "ambiguous" in pred.note


@pytest.mark.parametrize(
    "expression,variables",
    [
        ("system(cmd)", ["cmd"]),
        ("len = 1", ["len"]),
        ("len; shell echo owned", ["len"]),
        ("len\nshell echo owned", ["len"]),
        ("len\n>= max", ["len", "max"]),
        ("len >= max\n", ["len", "max"]),
        ("obj.field > 1", ["obj"]),
        ("*ptr", ["ptr"]),
        ("len > 1", ["len; shell"]),
        ("len > 1", ["len\n"]),
        ("len > 1", []),
        ("len > 1", ["len", "len"]),
    ],
)
def test_extract_rejects_side_effectful_or_non_identifier_material(expression, variables):
    pred = pp.extract_predicate(
        "+    if (len > 1) return;",
        VULN_SRC,
        _GuardLLM(condition_expr=expression, controlled_vars=variables),
    )
    assert not pred.localizable
    assert pred.validation_error


def test_resolve_anchor_exact_and_whitespace():
    src = "int a;\n    dst[len]   =  src[len];\nreturn;\n"
    assert pp.resolve_anchor(src, "dst[len]   =  src[len];") == 2
    # whitespace-normalized fallback
    assert pp.resolve_anchor(src, "dst[len] = src[len];") == 2
    assert pp.resolve_anchor(src, "nonexistent") is None


def test_expression_allows_horizontal_outer_whitespace():
    assert pp.validate_predicate_expression(" \tlen >= max\t ", ["len", "max"]) == [
        "len",
        ">=",
        "max",
    ]


# --- probe construction -----------------------------------------------------

def test_instrument_builds_conditional_bp():
    pred = pp.extract_predicate("<diff>", VULN_SRC, _GuardLLM())
    probe = pp.instrument(pred, "/build", binary="target", source_file="foo.c")
    assert probe.bp_spec == "foo.c:4"
    assert probe.condition == "len >= max"
    assert probe.binary == "/build/target"
    args = probe.gdb_argv(["input.bin"])
    commands = probe.mi_commands("/tmp/inferior.txt").decode()
    assert "--interpreter=mi2" in args
    assert "--args" in args and "/build/target" in args and "input.bin" in args
    assert '102-break-insert -c "len >= max" "foo.c:4"' in commands
    assert "104-stack-list-variables --simple-values" in commands
    assert "print len" not in commands


def test_instrument_rejects_non_localizable():
    pred = pp.extract_predicate("<diff>", VULN_SRC, _RewriteLLM())
    with pytest.raises(ValueError):
        pp.instrument(pred, "/build", binary="target")


# --- structured, isolated GDB/MI parsing -----------------------------------

def test_parse_mi_requires_bound_breakpoint_and_variables():
    output = (
        '102^done,bkpt={number="1",type="breakpoint"}\n'
        '103^running\n'
        '*stopped,reason="breakpoint-hit",bkptno="1",frame={func="copy_it"}\n'
        '104^done,variables=[{name="len",value="8"},{name="max",value="8"}]\n'
    )
    evidence = pp._parse_mi(output, ["len", "max"])
    assert evidence.observed
    assert evidence.state == {"len": "8", "max": "8"}
    assert not evidence.error


def test_inferior_text_cannot_spoof_mi_hit():
    spoof = 'Breakpoint 1, fake\n$1 = forged\n*stopped,reason="breakpoint-hit",bkptno="1"\n'
    evidence = pp._parse_mi(spoof, ["len"])
    assert not evidence.observed
    assert evidence.error


def test_parse_mi_clean_exit_is_not_observed():
    output = (
        '102^done,bkpt={number="1"}\n103^running\n'
        '*stopped,reason="exited-normally"\n104^error,msg="No frame"\n'
    )
    evidence = pp._parse_mi(output, ["len"])
    assert not evidence.observed
    assert not evidence.error


@pytest.mark.parametrize(
    "output,error",
    [
        ('102^error,msg="No symbol \\"len\\""\n', "No symbol"),
        ('102^done,bkpt={number="1"}\n', "run was not acknowledged"),
        (
            '102^done,bkpt={number="1"}\n103^running\n'
            '*stopped,reason="signal-received"\n',
            "stopped unexpectedly",
        ),
        (
            '102^done,bkpt={number="1"}\n103^running\n'
            '*stopped,reason="breakpoint-hit",bkptno="1"\n104^done,variables=[]\n',
            "variables unavailable",
        ),
    ],
)
def test_parse_mi_setup_and_evidence_failures_are_inconclusive(output, error):
    evidence = pp._parse_mi(output, ["len"])
    assert not evidence.observed
    assert error in evidence.error


def _probe(*, bound=False):
    return pp.InstrumentedProbe(
        binary=sys.executable,
        bp_spec="foo.c:4",
        condition="len >= max",
        controlled_vars=["len", "max"],
        source_file="foo.c",
        mechanically_bound=bound,
        binding_digest_sha256="b" * 64 if bound else "",
    )


def test_confirm_fails_closed_without_sandbox():
    verdict = pp.confirm(_probe(), b"9", vector="argv")
    assert verdict.inconclusive
    assert "requires an explicit" in verdict.error


def test_confirm_rejects_invalid_stdin_and_nul_vectors_before_sandbox():
    sandbox = _FakeSandbox()
    assert pp.confirm(_probe(), b"x", vector="typo").inconclusive
    assert "unsupported" in pp.confirm(_probe(), b"x", vector="stdin").error
    verdict = pp.confirm(_probe(), b"a\x00b", sandbox=sandbox, vector="argv")
    assert verdict.inconclusive
    assert "NUL" in verdict.error
    assert not sandbox.requests


@pytest.mark.parametrize(
    "condition,bp_spec",
    [
        ("system(len)", "foo.c:4"),
        ("len >= max", "foo.c:4 -ex shell"),
    ],
)
def test_confirm_revalidates_direct_probe_before_sandbox(condition, bp_spec):
    sandbox = _FakeSandbox()
    probe = _probe()
    probe.condition = condition
    probe.bp_spec = bp_spec
    verdict = pp.confirm(probe, b"9", sandbox=sandbox, vector="argv")
    assert verdict.inconclusive
    assert verdict.error
    assert not sandbox.requests


def test_observation_requires_complete_binding_metadata():
    output = (
        b'102^done,bkpt={number="1"}\n103^running\n'
        b'*stopped,reason="breakpoint-hit",bkptno="1"\n'
        b'104^done,variables=[{name="len",value="9"},{name="max",value="8"}]\n'
    )

    probe = _probe(bound=True)
    probe.binding_digest_sha256 = ""
    verdict = pp.confirm(probe, b"9", sandbox=_FakeSandbox(mi_output=output), vector="argv")
    assert verdict.observed
    assert not verdict.mechanically_bound
    assert not verdict.confirmed


def test_unbound_structured_hit_is_observation_not_confirmation():
    output = (
        b'102^done,bkpt={number="1"}\n103^running\n'
        b'*stopped,reason="breakpoint-hit",bkptno="1"\n'
        b'104^done,variables=[{name="len",value="9"},{name="max",value="8"}]\n'
    )

    verdict = pp.confirm(
        _probe(bound=False), b"9", sandbox=_FakeSandbox(mi_output=output), vector="argv"
    )
    assert verdict.observed
    assert not verdict.confirmed
    assert not verdict.inconclusive


def test_timeout_requires_process_tree_termination_attestation():
    sandbox = _FakeSandbox(timed_out=True, returncode=None, process_tree_terminated=True)
    verdict = pp.confirm(_probe(), b"9", sandbox=sandbox, vector="argv", timeout=0.01)
    assert verdict.inconclusive
    assert verdict.error == "timeout"
    assert sandbox.requests[0].process_tree_termination_required
    unsafe = _FakeSandbox(timed_out=True, returncode=None, process_tree_terminated=False)
    verdict = pp.confirm(_probe(), b"9", sandbox=unsafe, vector="argv", timeout=0.01)
    assert "without process-tree termination" in verdict.error


@pytest.mark.parametrize(
    "sandbox,error",
    [
        (_FakeSandbox(isolation="host"), "isolation"),
        (_FakeSandbox(network_disabled=False), "containment"),
        (_FakeSandbox(resource_limits_enforced=False), "containment"),
        (_FakeSandbox(output_limit_enforced=False), "containment"),
        (_FakeSandbox(target_digest_verified=False), "verify target digest"),
        (_FakeSandbox(input_digest_verified=False), "verify input digest"),
    ],
)
def test_confirm_rejects_missing_or_host_boundary_attestation(sandbox, error):
    verdict = pp.confirm(_probe(), b"9", sandbox=sandbox, vector="argv")
    assert verdict.inconclusive
    assert error in verdict.error


# --- real mechanical confirm on a toy -g binary ----------------------------

TOY_C = textwrap.dedent(
    """\
    #include <stdio.h>
    #include <stdlib.h>
    static char buf[8];
    void copy_it(int len, int max) {
        buf[0] = (char)len;            /* SINK: guarded operation */
    }
    int main(int argc, char **argv) {
        int len = atoi(argv[1]);
        int max = 8;
        copy_it(len, max);
        printf("ok len=%d\\n", len);
        return 0;
    }
    """
)


@pytest.fixture
def toy_probe(tmp_path):
    src = tmp_path / "toy.c"
    src.write_text(TOY_C)
    binp = tmp_path / "toy"
    subprocess.run(["gcc", "-g", "-O0", "-o", str(binp), str(src)], check=True)
    # sink line = the `buf[0] = (char)len;` line
    line = next(i for i, ln in enumerate(TOY_C.splitlines(), 1) if "buf[0]" in ln)
    pred = pp.PatchPredicate(
        file="toy.c", function="copy_it", condition_expr="len >= max",
        controlled_vars=["len", "max"], anchor_hint="buf[0]", kind="bounds",
        single_guard=True, confidence=0.9, line_anchor=line,
        mechanically_bound=True, binding_digest_sha256="a" * 64,
    )
    return pp.instrument(pred, tmp_path, binary="toy", source_file="toy.c")


@pytest.mark.skipif(not HAVE_CONTAINED_GDB, reason="needs gcc + gdb inside a container")
def test_confirm_benign_input_does_not_fire(toy_probe):
    # len=2 < max=8 -> predicate false -> probe silent -> NOT confirmed
    v = pp.confirm(toy_probe, b"2", sandbox=CONTAINED_GDB, vector="argv")
    assert v.error == ""
    assert v.probe_fired is False
    assert v.confirmed is False
    assert v.hit_count == 0
    assert not v.observed
    assert not v.inconclusive


@pytest.mark.skipif(not HAVE_CONTAINED_GDB, reason="needs gcc + gdb inside a container")
def test_confirm_trigger_input_fires_with_state(toy_probe):
    # len=42 >= max=8 -> predicate true on live state -> CONFIRMED
    v = pp.confirm(toy_probe, b"42", sandbox=CONTAINED_GDB, vector="argv")
    assert v.error == ""
    assert v.probe_fired is True
    assert v.observed is True
    assert v.confirmed is True
    assert v.hit_count >= 1
    # the mechanical evidence: the live controlled state at the hit
    assert v.controlled_state.get("len") == "42"
    assert v.controlled_state.get("max") == "8"


@pytest.mark.skipif(not HAVE_CONTAINED_GDB, reason="needs gcc + gdb inside a container")
def test_inferior_output_cannot_spoof_structured_hit(tmp_path):
    source = textwrap.dedent(
        r'''\
        #include <stdio.h>
        #include <stdlib.h>
        void sink(int len, int max) {
            puts("102^done,bkpt={number=\"1\"}");
            puts("*stopped,reason=\"breakpoint-hit\",bkptno=\"1\"");
            puts("104^done,variables=[{name=\"len\",value=\"99\"}]");
        }
        int main(int argc, char **argv) {
            int len = atoi(argv[1]);
            int max = 8;
            sink(len, max);
            return 0;
        }
        '''
    )
    src = tmp_path / "spoof.c"
    src.write_text(source)
    binary = tmp_path / "spoof"
    subprocess.run(["gcc", "-g", "-O0", "-o", str(binary), str(src)], check=True)
    line = next(i for i, text in enumerate(source.splitlines(), 1) if "puts(" in text)
    probe = pp.InstrumentedProbe(
        binary=str(binary),
        bp_spec=f"spoof.c:{line}",
        condition="len >= max",
        controlled_vars=["len", "max"],
        source_file="spoof.c",
        mechanically_bound=True,
        binding_digest_sha256="c" * 64,
    )
    verdict = pp.confirm(probe, b"2", sandbox=CONTAINED_GDB, vector="argv")
    assert not verdict.inconclusive
    assert not verdict.observed
    assert not verdict.confirmed


@pytest.mark.skipif(not HAVE_CONTAINED_GDB, reason="needs gcc + gdb inside a container")
def test_debugger_setup_failure_is_inconclusive(toy_probe):
    bad_probe = pp.InstrumentedProbe(
        binary=toy_probe.binary,
        bp_spec="missing-source.c:999",
        condition=toy_probe.condition,
        controlled_vars=toy_probe.controlled_vars,
        source_file="missing-source.c",
    )
    verdict = pp.confirm(bad_probe, b"42", sandbox=CONTAINED_GDB, vector="argv")
    assert verdict.inconclusive
    assert verdict.error
    assert not verdict.observed


@pytest.mark.skipif(not HAVE_CONTAINED_GDB, reason="needs gcc + gdb inside a container")
def test_orchestrate_end_to_end_toy(tmp_path):
    src = tmp_path / "foo.c"
    # reuse toy but named foo.c so the mock predicate's file matches
    src.write_text(TOY_C.replace("toy.c", "foo.c"))
    subprocess.run(["gcc", "-g", "-O0", "-o", str(tmp_path / "target"), str(src)], check=True)

    class _ToyLLM:
        def complete_json(self, system, prompt, schema):
            return {
                "single_guard": True, "file": "foo.c", "function": "copy_it",
                "condition_expr": "len >= max", "controlled_vars": ["len", "max"],
                "anchor_hint": "buf[0]", "kind": "bounds", "confidence": 0.9,
            }

    run = pp.confirm_by_patch_predicate(
        "+    if (len >= max) return;", TOY_C, tmp_path, [b"2", b"99"], _ToyLLM(),
        binary="target", source_file="foo.c", vector="argv", sandbox=CONTAINED_GDB,
    )
    assert run.predicate.localizable
    assert run.predicate.mechanically_bound
    assert [v.confirmed for v in run.verdicts] == [False, True]
    assert [v.observed for v in run.verdicts] == [False, True]
    assert run.any_confirmed
    assert run.any_observed
