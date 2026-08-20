"""Stage — the **patch-predicate oracle**: a confirm-gate that generalizes
0verse's confirmation BEYOND memory-safety, to the logic / integer / state bugs a
sanitizer cannot see.

The spine's PoV oracle proves a bug by *observing a crash* (a signal, or an ASan
report). That only fires for memory-safety faults. A huge class of CVEs — integer
truncation, missing length/state checks, off-by-one bounds — corrupt *logic*, not
memory, and never trip a sanitizer. For those, "did it crash?" is the wrong
question. The right question is the one the *fix* answers:

    the security patch ADDS a guard — a boolean condition that, when true, means
    "this input WOULD have triggered the bug". The oracle instruments that exact
    condition as a runtime PROBE into the UNPATCHED build, at the exact program
    point the fix guards, and evaluates it against LIVE program state.

An input OBSERVES the proposed condition iff execution reaches the probe and the
condition evaluates true. That observation becomes mechanically patch-bound only
when the exact safe-expression token sequence occurs uniquely in an added guard;
otherwise it remains non-authoritative. Even a bound observation does not prove a
vulnerability, exploitability, impact, novelty, bounty eligibility, or disclosure
readiness. An LLM proposes structure, while isolated GDB/MI evidence records runtime
state without granting the model vulnerability or disclosure authority.

Design of the mechanical layer — **instrumentation choice**: a GDB *conditional
breakpoint* over the ``-g`` vulnerable build, NOT a source rewrite + rebuild. We
set ``break <file>:<line> if <condition>`` at the sink and run the candidate input.
Rationale:
  * no recompile — works on the vulnerable artifact as built, so we never risk the
    instrumentation changing the very codegen we are probing;
  * the condition is a real C expression evaluated by GDB against DWARF-resolved
    locals (the ``-g`` build) — same semantics as the source guard, zero
    hand-translation;
  * the breakpoint *hit* is structured GDB/MI evidence; inferior output is routed
    away from the debugger channel so the target cannot forge a hit record;
  * conditions use a side-effect-free expression grammar, and controlled variables
    are identifier-only stack-variable listings rather than debugger expressions.
  * target execution has no local-process default: callers must supply an explicit
    container, VM, or remote-worker sandbox that disables networking, caps input,
    output, and time, and kills the complete debugger/inferior process tree.
The cost is a live GDB run per input (fine for a confirm-gate, which runs on the
handful of candidate inputs that already passed cheaper filters). A source-insert
``if (cond) __patch_pred_hit();`` variant is possible for hot loops but is left as
a documented alternative — the GDB path is strictly more robust for the localized
single-guard shape this stage targets.

Scope / honesty: predicate extraction is tractable for the **single added guard at
a sink** shape (a bounds/length/state check the fix inserts). For algorithmic
rewrites — the fix restructures a loop, changes an allocation strategy, rewrites a
parser — there is no single localizable predicate, and ``extract_predicate`` says
so (``single_guard=False``) rather than fabricating one. That honest fallthrough is
the point: the oracle confirms what it can prove and abstains otherwise.

Unlike the general execution contract's opt-in ``LocalProcessBackend``, this module
does not expose any host debugger runner. Without a sandbox boundary, confirmation
fails closed as inconclusive before GDB or the candidate binary can be launched.
Sandbox result flags are assertions by an operator-selected, audited backend—not
cryptographic proof that containment occurred. Untrusted or caller-supplied backend
implementations must not be accepted as a security boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_SOURCE_BASENAME_RE = re.compile(r"[A-Za-z0-9_.+\-]+\Z")
_BREAKPOINT_SPEC_RE = re.compile(r"[A-Za-z0-9_.+\-]+:[1-9][0-9]*\Z")
_BINDING_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_SANDBOX_ISOLATION_MODES = frozenset({"container", "vm", "remote-worker"})
MAX_PREDICATE_INPUT_BYTES = 1024 * 1024
MAX_PREDICATE_TIMEOUT_SECONDS = 60.0
MAX_PREDICATE_OUTPUT_BYTES = 1024 * 1024
_TOKEN_RE = re.compile(
    r"[ \t]*(?:(0[xX][0-9A-Fa-f]+[uUlL]*|[0-9]+[uUlL]*)"
    r"|([A-Za-z_][A-Za-z0-9_]*)"
    r"|(\|\||&&|==|!=|<=|>=|<<|>>|[()!~+\-*/%<>&|^]))"
)
_BINARY_PRECEDENCE = {
    "||": 1,
    "&&": 2,
    "|": 3,
    "^": 4,
    "&": 5,
    "==": 6,
    "!=": 6,
    "<": 7,
    "<=": 7,
    ">": 7,
    ">=": 7,
    "<<": 8,
    ">>": 8,
    "+": 9,
    "-": 9,
    "*": 10,
    "/": 10,
    "%": 10,
}
_UNARY_OPERATORS = {"!", "~", "+", "-"}


class _ExpressionError(ValueError):
    pass


def _tokenize_expression(expression: str) -> list[str]:
    """Tokenize the deliberately small, side-effect-free predicate language."""
    if not expression or len(expression) > 512:
        raise _ExpressionError("predicate expression is empty or too long")
    if "\n" in expression or "\r" in expression:
        raise _ExpressionError("predicate expression must be a single line")
    expression = expression.strip(" \t")
    if not expression:
        raise _ExpressionError("predicate expression is empty or too long")
    tokens: list[str] = []
    pos = 0
    while pos < len(expression):
        match = _TOKEN_RE.match(expression, pos)
        if match is None:
            raise _ExpressionError(f"unsafe predicate token at offset {pos}")
        token = next(group for group in match.groups() if group is not None)
        tokens.append(token)
        pos = match.end()
    return tokens


class _ExpressionParser:
    def __init__(self, tokens: list[str], allowed_identifiers: set[str]) -> None:
        self.tokens = tokens
        self.allowed_identifiers = allowed_identifiers
        self.pos = 0

    def parse(self) -> None:
        self._expression(1)
        if self.pos != len(self.tokens):
            raise _ExpressionError(f"unexpected predicate token {self.tokens[self.pos]!r}")

    def _expression(self, minimum_precedence: int) -> None:
        self._unary()
        while self.pos < len(self.tokens):
            operator = self.tokens[self.pos]
            precedence = _BINARY_PRECEDENCE.get(operator)
            if precedence is None or precedence < minimum_precedence:
                return
            self.pos += 1
            self._expression(precedence + 1)

    def _unary(self) -> None:
        if self.pos >= len(self.tokens):
            raise _ExpressionError("predicate expression ended unexpectedly")
        token = self.tokens[self.pos]
        if token in _UNARY_OPERATORS:
            self.pos += 1
            self._unary()
            return
        if token == "(":
            self.pos += 1
            self._expression(1)
            if self.pos >= len(self.tokens) or self.tokens[self.pos] != ")":
                raise _ExpressionError("predicate has unbalanced parentheses")
            self.pos += 1
            return
        if _IDENT_RE.fullmatch(token):
            if token not in self.allowed_identifiers:
                raise _ExpressionError(f"predicate identifier {token!r} is not controlled")
            self.pos += 1
            return
        if re.fullmatch(r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)[uUlL]*", token):
            self.pos += 1
            return
        raise _ExpressionError(f"unexpected predicate token {token!r}")


def validate_predicate_expression(expression: str, controlled_vars: list[str]) -> list[str]:
    """Return canonical tokens or reject anything capable of side effects.

    The accepted language is identifiers, integer literals, parentheses, and C's
    arithmetic/bitwise/comparison/logical operators. Calls, member access, pointer
    dereference, assignment, comma, casts, strings, and GDB syntax are intentionally
    outside the language. This makes an LLM proposal data, never debugger code.
    """
    if not controlled_vars or any(_IDENT_RE.fullmatch(name) is None for name in controlled_vars):
        raise _ExpressionError("controlled_vars must be non-empty C identifiers")
    if len(set(controlled_vars)) != len(controlled_vars):
        raise _ExpressionError("controlled_vars must be unique")
    tokens = _tokenize_expression(expression)
    _ExpressionParser(tokens, set(controlled_vars)).parse()
    return tokens


def _added_guard_conditions(fix_diff: str) -> list[list[str]]:
    """Extract tokenized one-line ``if (<condition>)`` guards added by a diff.

    This is intentionally conservative. Multiline guards, polarity rewrites, and
    complex expressions remain observable but cannot gain a mechanical binding.
    """
    conditions: list[list[str]] = []
    for raw_line in fix_diff.splitlines():
        if not raw_line.startswith("+") or raw_line.startswith("+++"):
            continue
        line = raw_line[1:].lstrip()
        match = re.match(r"if\s*\(", line)
        if match is None:
            continue
        start = match.end()
        depth = 1
        end: int | None = None
        for index in range(start, len(line)):
            if line[index] == "(":
                depth += 1
            elif line[index] == ")":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        if end is None:
            continue
        try:
            conditions.append(_tokenize_expression(line[start:end]))
        except _ExpressionError:
            continue
    return conditions


def _binding_digest(
    fix_diff: str, vuln_source: str, predicate: PatchPredicate, tokens: list[str]
) -> str:
    material = {
        "anchor_hint": predicate.anchor_hint,
        "condition_tokens": tokens,
        "file": predicate.file,
        "fix_diff_sha256": hashlib.sha256(fix_diff.encode()).hexdigest(),
        "function": predicate.function,
        "line_anchor": predicate.line_anchor,
        "vuln_source_sha256": hashlib.sha256(vuln_source.encode()).hexdigest(),
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(b"0verse-patch-predicate-binding-v1\0" + encoded).hexdigest()

# --- LLM contract (a subset of zeroverse.agent.LLM) ------------------------

class _LLM(Protocol):
    def complete_json(
        self, system: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any]: ...


# --- the extracted predicate ------------------------------------------------

@dataclass
class PatchPredicate:
    """The trigger condition a security fix ADDED, in the polarity that means
    "this input would have been rejected == would have triggered the bug".

    ``condition_expr`` is a C boolean expression over ``controlled_vars`` (live
    locals/fields at the sink). ``trigger_value`` is the value of the expression
    that means *bug-triggering*; by convention we normalize ``condition_expr`` so
    that ``trigger_value`` is ``True`` (the expression IS the "would-reject"
    predicate). ``line_anchor`` is a line number in the VULNERABLE source (resolved
    mechanically from ``anchor_hint`` — the fix's line numbers do not match the
    vulnerable file)."""

    file: str
    function: str
    condition_expr: str            # C expr, trigger polarity (True == would-reject)
    controlled_vars: list[str]
    anchor_hint: str               # a source substring at the sink, to locate the line
    kind: str                      # bounds | length | integer | state | ...
    single_guard: bool             # False -> no localizable predicate (algorithmic rewrite)
    confidence: float = 0.0
    line_anchor: int | None = None # line in the vulnerable file (resolved)
    trigger_value: bool = True
    note: str = ""
    mechanically_bound: bool = False
    binding_digest_sha256: str = ""
    validation_error: str = ""

    @property
    def localizable(self) -> bool:
        """Ready to observe, but not necessarily authoritative or patch-bound."""
        return (
            self.single_guard
            and self.line_anchor is not None
            and not self.validation_error
        )

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> PatchPredicate:
        cv = d.get("controlled_vars") or []
        if isinstance(cv, str):
            cv = [v.strip(" \t") for v in cv.split(",") if v.strip(" \t")]
        return cls(
            file=str(d.get("file", "")).strip(),
            function=str(d.get("function", "")).strip(),
            condition_expr=str(d.get("condition_expr", "")).strip(" \t"),
            controlled_vars=[str(v).strip(" \t") for v in cv],
            anchor_hint=str(d.get("anchor_hint", "")).strip(),
            kind=str(d.get("kind", "unknown")).strip(),
            single_guard=bool(d.get("single_guard", False)),
            confidence=float(d.get("confidence", 0.0) or 0.0),
            note=str(d.get("note", "")).strip(),
        )


_PREDICATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "single_guard": {"type": "boolean"},
        "file": {"type": "string"},
        "function": {"type": "string"},
        "condition_expr": {"type": "string"},
        "controlled_vars": {"type": "array", "items": {"type": "string"}},
        "anchor_hint": {"type": "string"},
        "kind": {"type": "string"},
        "confidence": {"type": "number"},
        "note": {"type": "string"},
    },
    "required": ["single_guard", "condition_expr", "anchor_hint"],
}

_EXTRACT_SYSTEM = (
    "You are a vulnerability-fix analyst. You are given a SECURITY FIX diff and the "
    "VULNERABLE source it patches. A fix of the tractable shape ADDS a single guard "
    "at a sink — a boolean check that REJECTS (returns/errors/skips) inputs that "
    "would trigger the bug. Your job: extract that guard as a machine-checkable "
    "predicate.\n\n"
    "Return the condition in TRIGGER polarity: the boolean expression that is TRUE "
    "exactly for the inputs the fix now rejects (i.e. the bug-triggering state). If "
    "the fix adds `if (len < max) { ...safe... }` guarding a sink (so it now SKIPS "
    "the sink when len >= max), the trigger predicate is `len >= max`. If it adds "
    "`if (n > CAP) return -EINVAL;`, the trigger predicate is `n > CAP`.\n\n"
    "`anchor_hint` MUST be a verbatim substring of ONE line in the VULNERABLE source "
    "at the exact program point where the condition should be evaluated (the sink "
    "line — the dangerous operation the guard protects). Use variable/field names as "
    "they appear in the VULNERABLE source so the expression compiles against its "
    "live locals.\n\n"
    "If the fix is an ALGORITHMIC REWRITE (restructured loop, changed allocation, "
    "rewritten parser) with NO single localizable guard, set single_guard=false and "
    "explain in `note`. Never fabricate a predicate. Propose only — a mechanical "
    "probe decides."
)


def _extract_prompt(fix_diff: str, vuln_source: str) -> str:
    return (
        "SECURITY FIX diff:\n```diff\n" + fix_diff.strip() + "\n```\n\n"
        "VULNERABLE source (the code the diff patches; use these variable names):\n"
        "```c\n" + vuln_source.strip() + "\n```\n\n"
        "Extract the added guard as a trigger predicate. Return JSON with: "
        "single_guard, condition_expr (trigger polarity), controlled_vars, "
        "anchor_hint (verbatim substring of the vulnerable sink line), file, "
        "function, kind, confidence, note."
    )


def _anchor_matches(vuln_source: str, anchor_hint: str) -> list[int]:
    if not anchor_hint:
        return []
    lines = vuln_source.splitlines()
    exact = [i for i, line in enumerate(lines, 1) if anchor_hint in line]
    if exact:
        return exact
    normalized = re.sub(r"\s+", " ", anchor_hint).strip()
    if not normalized:
        return []
    return [
        i
        for i, line in enumerate(lines, 1)
        if normalized in re.sub(r"\s+", " ", line).strip()
    ]


def resolve_anchor(vuln_source: str, anchor_hint: str) -> int | None:
    """Map ``anchor_hint`` to a 1-based line number in ``vuln_source`` (mechanical:
    the fix's line numbers are for the PATCHED file and do not match the vulnerable
    one). Returns the line of the first exact-substring match, else a whitespace-
    normalized match. Ambiguous matches abstain instead of silently selecting the
    first occurrence."""
    matches = _anchor_matches(vuln_source, anchor_hint)
    return matches[0] if len(matches) == 1 else None


def extract_predicate(fix_diff: str, vuln_source: str, llm: _LLM) -> PatchPredicate:
    """LLM parses the fix diff into a structured trigger predicate, then we resolve
    the sink line mechanically against the vulnerable source. The LLM only PROPOSES
    structure (condition + where); it never confirms anything."""
    raw = llm.complete_json(_EXTRACT_SYSTEM, _extract_prompt(fix_diff, vuln_source),
                            _PREDICATE_SCHEMA)
    pred = PatchPredicate.from_json(raw)
    if not pred.single_guard:
        if not pred.note:
            pred.note = "no localizable single-guard predicate (algorithmic rewrite)"
        return pred
    matches = _anchor_matches(vuln_source, pred.anchor_hint)
    pred.line_anchor = matches[0] if len(matches) == 1 else None
    if pred.line_anchor is None:
        reason = (
            "anchor_hint is ambiguous in the vulnerable source; cannot localize the probe"
            if len(matches) > 1
            else "anchor_hint did not match any line in the vulnerable source; "
            "cannot localize the probe"
        )
        pred.note = ((pred.note + " ") if pred.note else "") + reason
        return pred
    try:
        tokens = validate_predicate_expression(pred.condition_expr, pred.controlled_vars)
    except _ExpressionError as error:
        pred.validation_error = str(error)
        pred.note = ((pred.note + " ") if pred.note else "") + (
            f"unsafe or unsupported predicate: {error}"
        )
        return pred
    added_conditions = _added_guard_conditions(fix_diff)
    pred.mechanically_bound = added_conditions.count(tokens) == 1
    if pred.mechanically_bound:
        pred.binding_digest_sha256 = _binding_digest(fix_diff, vuln_source, pred, tokens)
    else:
        pred.note = ((pred.note + " ") if pred.note else "") + (
            "predicate was not uniquely token-identical to a one-line added guard; "
            "hits remain non-authoritative observations"
        )
    return pred


# --- instrumentation: a GDB conditional-breakpoint probe --------------------

@dataclass
class InstrumentedProbe:
    """A validated, observation-only GDB/MI conditional breakpoint probe."""

    binary: str
    bp_spec: str                   # "inflate.c:764"
    condition: str                 # C expr evaluated by GDB against live locals
    controlled_vars: list[str]
    source_file: str = ""
    mechanically_bound: bool = False
    binding_digest_sha256: str = ""

    def gdb_argv(self, run_argv: list[str], *, debugger: str = "gdb") -> list[str]:
        return [
            debugger,
            "--nx",
            "--quiet",
            "--interpreter=mi2",
            "--args",
            self.binary,
            *run_argv,
        ]

    def mi_commands(self, inferior_tty: str) -> bytes:
        """Build tokenized MI commands; variables are listed, never evaluated."""
        condition = json.dumps(self.condition)
        breakpoint = json.dumps(self.bp_spec)
        tty = json.dumps(inferior_tty)
        commands = [
            "100-gdb-set pagination off",
            f"101-inferior-tty-set {tty}",
            f"102-break-insert -c {condition} {breakpoint}",
            "103-exec-run",
            "104-stack-list-variables --simple-values",
            "105-gdb-exit",
        ]
        return ("\n".join(commands) + "\n").encode()


@dataclass(frozen=True)
class PredicateSandboxRequest:
    """Bounded request for a mandatory out-of-host execution boundary.

    Implementations must execute GDB and the inferior only in the declared
    container, VM, or remote worker; isolate inferior output from GDB/MI; disable
    network access; cap each output stream while reading it (before allocation or
    transport); and terminate the complete process tree on timeout. No host-process
    implementation is provided by 0verse.
    """

    binary: str
    bp_spec: str
    condition: str
    controlled_vars: tuple[str, ...]
    source_file: str
    mechanically_bound: bool
    binding_digest_sha256: str
    target_sha256: str
    input_sha256: str
    candidate_input: bytes
    vector: str
    extra_argv: tuple[str, ...]
    timeout: float
    network_allowed: bool = False
    max_output_bytes: int = MAX_PREDICATE_OUTPUT_BYTES
    process_tree_termination_required: bool = True

    def __post_init__(self) -> None:
        if not Path(self.binary).is_absolute():
            raise ValueError("sandbox target must be an absolute path")
        if _BINDING_DIGEST_RE.fullmatch(self.target_sha256) is None:
            raise ValueError("sandbox target digest must be lowercase SHA-256")
        if _BINDING_DIGEST_RE.fullmatch(self.input_sha256) is None:
            raise ValueError("sandbox input digest must be lowercase SHA-256")
        if self.vector not in {"file", "argv"}:
            raise ValueError("sandbox request has unsupported input vector")
        validate_predicate_expression(self.condition, list(self.controlled_vars))
        if _BREAKPOINT_SPEC_RE.fullmatch(self.bp_spec) is None:
            raise ValueError("sandbox request has unsafe breakpoint specification")
        if len(self.candidate_input) > MAX_PREDICATE_INPUT_BYTES:
            raise ValueError("sandbox request input exceeds limit")
        if self.timeout <= 0 or self.timeout > MAX_PREDICATE_TIMEOUT_SECONDS:
            raise ValueError("sandbox request timeout exceeds limit")
        if self.network_allowed:
            raise ValueError("predicate sandbox requests cannot enable networking")
        if not self.process_tree_termination_required:
            raise ValueError("predicate sandbox must terminate the complete process tree")
        if not 0 < self.max_output_bytes <= MAX_PREDICATE_OUTPUT_BYTES:
            raise ValueError("sandbox output limit is invalid")
        if len(self.extra_argv) > 64 or any(
            len(item) > 4096 or "\x00" in item for item in self.extra_argv
        ):
            raise ValueError("sandbox request argv exceeds limit")


@dataclass(frozen=True)
class PredicateSandboxResult:
    """Raw debugger evidence returned by an enforced execution boundary."""

    isolation: str
    target_sha256: str
    input_sha256: str
    mi_output: bytes = b""
    debugger_stderr: bytes = b""
    inferior_output: bytes = b""
    returncode: int | None = None
    timed_out: bool = False
    process_tree_terminated: bool = False
    network_disabled: bool = False
    resource_limits_enforced: bool = False
    output_limit_enforced: bool = False
    target_digest_verified: bool = False
    input_digest_verified: bool = False
    error: str = ""

    def __post_init__(self) -> None:
        if self.isolation not in _SANDBOX_ISOLATION_MODES:
            raise ValueError(
                "predicate execution requires container, VM, or remote-worker isolation"
            )
        if _BINDING_DIGEST_RE.fullmatch(self.target_sha256) is None:
            raise ValueError("sandbox result target digest must be lowercase SHA-256")
        if _BINDING_DIGEST_RE.fullmatch(self.input_sha256) is None:
            raise ValueError("sandbox result input digest must be lowercase SHA-256")
        if not all(
            isinstance(value, bytes)
            for value in (self.mi_output, self.debugger_stderr, self.inferior_output)
        ):
            raise ValueError("sandbox debugger outputs must be bytes")
        if not all(
            isinstance(value, bool)
            for value in (
                self.timed_out,
                self.process_tree_terminated,
                self.network_disabled,
                self.resource_limits_enforced,
                self.output_limit_enforced,
                self.target_digest_verified,
                self.input_digest_verified,
            )
        ):
            raise ValueError("sandbox attestations must be booleans")


class PredicateExecutionSandbox(Protocol):
    """Mandatory boundary capable of containing untrusted target execution.

    The boundary must stage and re-hash the target and input inside isolation,
    enforce the request's network/resource/output policy, and attest those facts.
    These booleans are trusted-backend assertions, not cryptographic proof. The
    backend must cap streams during capture; the caller's later length check is
    defense in depth and cannot prevent a backend-side allocation.
    """

    def run(self, request: PredicateSandboxRequest) -> PredicateSandboxResult: ...


def instrument(
    predicate: PatchPredicate,
    target_build_dir: str | Path,
    *,
    binary: str | Path,
    source_file: str | None = None,
) -> InstrumentedProbe:
    """Build the mechanical probe for ``predicate`` over the vulnerable ``binary``.

    ``source_file`` is the sink source file name GDB keys the breakpoint on (defaults
    to ``predicate.file``'s basename). The binary MUST be built with ``-g`` so GDB
    can resolve the source line and the controlled locals; we do not rebuild it."""
    if not predicate.localizable:
        raise ValueError(
            f"predicate is not localizable ({predicate.note or 'no single guard'}); "
            "nothing to instrument"
        )
    src = source_file or Path(predicate.file).name or "??"
    if _SOURCE_BASENAME_RE.fullmatch(src) is None:
        raise ValueError("source_file must be a safe basename")
    validate_predicate_expression(predicate.condition_expr, predicate.controlled_vars)
    binpath = Path(target_build_dir) / binary if not Path(binary).is_absolute() else Path(binary)
    return InstrumentedProbe(
        binary=str(binpath),
        bp_spec=f"{src}:{predicate.line_anchor}",
        condition=predicate.condition_expr,
        controlled_vars=list(predicate.controlled_vars),
        source_file=src,
        mechanically_bound=predicate.mechanically_bound,
        binding_digest_sha256=predicate.binding_digest_sha256,
    )


# --- the mechanical verdict -------------------------------------------------

@dataclass
class PredicateVerdict:
    """Debugger observation with explicit authority and failure state.

    ``confirmed`` means only that a mechanically patch-bound predicate was
    observed. It does not assert vulnerability, exploitability, impact, novelty,
    bounty eligibility, or disclosure readiness, and no downstream consumer may
    promote it to any of those claims without independent evidence and review.
    """

    confirmed: bool
    probe_fired: bool
    hit_count: int
    observed: bool = False
    mechanically_bound: bool = False
    inconclusive: bool = False
    controlled_state: dict[str, str] = field(default_factory=dict)
    detail: str = ""
    error: str = ""


@dataclass
class _MiEvidence:
    observed: bool
    state: dict[str, str] = field(default_factory=dict)
    error: str = ""


_MI_BREAKPOINT_RE = re.compile(
    r'^102\^done,bkpt=\{[^\n]*number="((?:\\.|[^"\\])+)"', re.M
)
_MI_STOP_RE = re.compile(r'^\*stopped,reason="([^"]+)"([^\n]*)', re.M)
_MI_VARIABLE_RE = re.compile(
    r'\{[^{}\n]*name="((?:\\.|[^"\\])*)"[^{}\n]*'
    r'value="((?:\\.|[^"\\])*)"[^{}\n]*\}'
)


def _mi_unescape(value: str) -> str:
    try:
        decoded = json.loads(f'"{value}"')
    except json.JSONDecodeError as error:
        raise ValueError("malformed GDB/MI string") from error
    if not isinstance(decoded, str):
        raise ValueError("malformed GDB/MI string")
    return decoded


def _parse_mi(output: str, controlled_vars: list[str]) -> _MiEvidence:
    """Parse only GDB's MI channel; inferior output lives on a separate tty."""
    breakpoint_match = _MI_BREAKPOINT_RE.search(output)
    if breakpoint_match is None:
        error_match = re.search(r'^102\^error,msg="((?:\\.|[^"\\])*)"', output, re.M)
        detail = (
            _mi_unescape(error_match.group(1))
            if error_match
            else "breakpoint setup not acknowledged"
        )
        return _MiEvidence(False, error=detail)
    breakpoint_number = _mi_unescape(breakpoint_match.group(1))
    if "103^running" not in output:
        return _MiEvidence(False, error="inferior run was not acknowledged")
    stop_match = _MI_STOP_RE.search(output)
    if stop_match is None:
        return _MiEvidence(False, error="GDB/MI emitted no terminal stop record")
    reason, payload = stop_match.groups()
    if reason in {"exited-normally", "exited"}:
        return _MiEvidence(False)
    if reason != "breakpoint-hit":
        return _MiEvidence(False, error=f"inferior stopped unexpectedly: {reason}")
    hit_match = re.search(r'bkptno="((?:\\.|[^"\\])+)"', payload)
    if hit_match is None or _mi_unescape(hit_match.group(1)) != breakpoint_number:
        return _MiEvidence(False, error="stop record did not bind to the installed breakpoint")
    variables_result = re.search(r'^104\^done,variables=\[(.*)\]$', output, re.M)
    if variables_result is None:
        return _MiEvidence(False, error="controlled-variable evidence is missing")
    all_state = {
        _mi_unescape(name): _mi_unescape(value)
        for name, value in _MI_VARIABLE_RE.findall(variables_result.group(1))
    }
    missing = [name for name in controlled_vars if name not in all_state]
    if missing:
        return _MiEvidence(False, error=f"controlled variables unavailable: {', '.join(missing)}")
    return _MiEvidence(True, {name: all_state[name] for name in controlled_vars})


def _resolve_binary(binary: str) -> str | None:
    path = Path(binary)
    if path.exists():
        return str(path.resolve()) if path.is_file() else None
    return shutil.which(binary)


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def confirm(
    probe: InstrumentedProbe,
    candidate_input: bytes,
    *,
    sandbox: PredicateExecutionSandbox | None = None,
    vector: str = "file",
    extra_argv: list[str] | None = None,
    timeout: float = 30.0,
) -> PredicateVerdict:
    """Observe a predicate only through a mandatory out-of-host sandbox.

    ``vector`` mirrors the oracle's delivery convention: ``file`` writes the bytes to
    a temp file and passes its path as argv[1] (the harness reads it); ``stdin``
    feeds them on standard input; ``argv`` passes them as a single argument. A hit
    is authoritative only when extraction mechanically bound the exact token
    sequence to one added guard. Otherwise it remains an observation. Vulnerability
    and disclosure authority are always outside this primitive. If ``sandbox`` is
    absent, this function fails closed without launching GDB or the target."""
    if vector not in {"file", "argv", "stdin"}:
        return PredicateVerdict(
            False, False, 0, inconclusive=True, error="unsupported input vector"
        )
    if vector == "stdin":
        return PredicateVerdict(
            False,
            False,
            0,
            inconclusive=True,
            error="stdin vector is unsupported by the isolated GDB/MI runner",
        )
    if sandbox is None:
        return PredicateVerdict(
            False,
            False,
            0,
            inconclusive=True,
            error=(
                "predicate execution requires an explicit container, VM, "
                "or remote-worker sandbox"
            ),
        )
    if len(candidate_input) > MAX_PREDICATE_INPUT_BYTES:
        return PredicateVerdict(
            False, False, 0, inconclusive=True, error="candidate input exceeds sandbox limit"
        )
    if timeout <= 0 or timeout > MAX_PREDICATE_TIMEOUT_SECONDS:
        return PredicateVerdict(
            False, False, 0, inconclusive=True, error="timeout exceeds sandbox limit"
        )
    argv_items = tuple(extra_argv or ())
    if (
        len(argv_items) > 64
        or any(len(item) > 4096 or "\x00" in item for item in argv_items)
    ):
        return PredicateVerdict(
            False, False, 0, inconclusive=True, error="extra argv exceeds sandbox limits"
        )
    try:
        validate_predicate_expression(probe.condition, probe.controlled_vars)
    except _ExpressionError as error:
        return PredicateVerdict(
            False,
            False,
            0,
            inconclusive=True,
            error=f"unsafe or unsupported probe predicate: {error}",
        )
    if _BREAKPOINT_SPEC_RE.fullmatch(probe.bp_spec) is None:
        return PredicateVerdict(
            False, False, 0, inconclusive=True, error="unsafe breakpoint specification"
        )
    resolved_binary = _resolve_binary(probe.binary)
    if resolved_binary is None:
        return PredicateVerdict(False, False, 0, inconclusive=True, error="binary unavailable")
    if vector == "argv":
        try:
            candidate_input.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return PredicateVerdict(
                False, False, 0, inconclusive=True, error="argv input is not UTF-8 text"
            )
        if b"\x00" in candidate_input:
            return PredicateVerdict(
                False, False, 0, inconclusive=True, error="argv input contains NUL"
            )
    target_sha256 = _sha256_file(resolved_binary)
    input_sha256 = hashlib.sha256(candidate_input).hexdigest()
    request = PredicateSandboxRequest(
        binary=resolved_binary,
        bp_spec=probe.bp_spec,
        condition=probe.condition,
        controlled_vars=tuple(probe.controlled_vars),
        source_file=probe.source_file,
        mechanically_bound=probe.mechanically_bound,
        binding_digest_sha256=probe.binding_digest_sha256,
        target_sha256=target_sha256,
        input_sha256=input_sha256,
        candidate_input=candidate_input,
        vector=vector,
        extra_argv=argv_items,
        timeout=timeout,
    )
    try:
        result = sandbox.run(request)
    except Exception as error:
        return PredicateVerdict(False, False, 0, inconclusive=True, error=str(error))
    if not isinstance(result, PredicateSandboxResult):
        return PredicateVerdict(
            False, False, 0, inconclusive=True, error="sandbox returned invalid evidence type"
        )
    if result.isolation not in _SANDBOX_ISOLATION_MODES:
        return PredicateVerdict(
            False, False, 0, inconclusive=True, error="sandbox reported unsafe isolation mode"
        )
    if result.target_sha256 != target_sha256:
        return PredicateVerdict(
            False, False, 0, inconclusive=True, error="sandbox target digest mismatch"
        )
    if result.input_sha256 != input_sha256:
        return PredicateVerdict(
            False, False, 0, inconclusive=True, error="sandbox input digest mismatch"
        )
    if not result.target_digest_verified:
        return PredicateVerdict(
            False, False, 0, inconclusive=True, error="sandbox did not verify target digest"
        )
    if not result.input_digest_verified:
        return PredicateVerdict(
            False, False, 0, inconclusive=True, error="sandbox did not verify input digest"
        )
    if (
        not result.network_disabled
        or not result.resource_limits_enforced
        or not result.output_limit_enforced
    ):
        return PredicateVerdict(
            False, False, 0, inconclusive=True, error="sandbox containment attestation missing"
        )
    output_size = sum(
        len(value)
        for value in (
            result.mi_output,
            result.debugger_stderr,
            result.inferior_output,
            result.error.encode("utf-8", "replace"),
        )
    )
    if output_size > request.max_output_bytes:
        return PredicateVerdict(
            False, False, 0, inconclusive=True, error="sandbox output exceeds limit"
        )
    if result.timed_out:
        timeout_error = (
            "timeout"
            if result.process_tree_terminated
            else "sandbox timeout without process-tree termination attestation"
        )
        return PredicateVerdict(False, False, 0, inconclusive=True, error=timeout_error)
    if result.error:
        return PredicateVerdict(False, False, 0, inconclusive=True, error=result.error)
    mi_output = result.mi_output.decode("utf-8", "replace")
    diagnostics = result.debugger_stderr.decode("utf-8", "replace")
    if result.returncode != 0:
        return PredicateVerdict(
            False,
            False,
            0,
            inconclusive=True,
            detail=(mi_output + diagnostics)[-800:],
            error=f"gdb exited with status {result.returncode}",
        )
    evidence = _parse_mi(mi_output, probe.controlled_vars)
    if evidence.error:
        return PredicateVerdict(
            False,
            False,
            0,
            inconclusive=True,
            detail=(mi_output + diagnostics)[-800:],
            error=evidence.error,
        )
    observed = evidence.observed
    mechanically_bound = (
        probe.mechanically_bound
        and _BINDING_DIGEST_RE.fullmatch(probe.binding_digest_sha256) is not None
    )
    confirmed = observed and mechanically_bound
    if confirmed:
        authority = "mechanically-bound observation"
    elif observed:
        authority = "non-authoritative observation"
    else:
        authority = "no predicate observation"
    return PredicateVerdict(
        confirmed=confirmed,
        probe_fired=observed,
        hit_count=1 if observed else 0,
        observed=observed,
        mechanically_bound=mechanically_bound,
        controlled_state=evidence.state,
        detail=(
            f"{authority}: breakpoint {probe.bp_spec} if ({probe.condition}); "
            f"inferior output isolated by {result.isolation} "
            f"({len(result.inferior_output)} byte(s))"
        ),
    )


# --- orchestration ----------------------------------------------------------

@dataclass
class PredicateRun:
    predicate: PatchPredicate
    verdicts: list[PredicateVerdict]
    probe: InstrumentedProbe | None = None

    @property
    def any_confirmed(self) -> bool:
        """True only for a hit mechanically bound to the supplied patch bytes."""
        return any(v.confirmed for v in self.verdicts)

    @property
    def any_observed(self) -> bool:
        return any(v.observed for v in self.verdicts)


def confirm_by_patch_predicate(
    fix_diff: str,
    vuln_source: str,
    vuln_build: str | Path,
    candidate_inputs: list[bytes],
    llm: _LLM,
    *,
    binary: str,
    source_file: str | None = None,
    vector: str = "file",
    extra_argv: list[str] | None = None,
    timeout: float = 30.0,
    sandbox: PredicateExecutionSandbox | None = None,
) -> PredicateRun:
    """End-to-end: extract the trigger predicate from the fix (LLM proposes), build
    the mechanical probe over the vulnerable binary, and run every candidate input
    through it. Returns the predicate + one observation verdict per input. Even a
    mechanically bound hit proves only that the supplied patch guard was reached;
    it does not prove vulnerability, exploitability, impact, novelty, bounty
    eligibility, or disclosure readiness.

    If the fix has no localizable single-guard predicate, returns a ``PredicateRun``
    with no probe and empty verdicts (honest abstention — the oracle confirms what it
    can prove)."""
    pred = extract_predicate(fix_diff, vuln_source, llm)
    if not pred.localizable:
        return PredicateRun(predicate=pred, verdicts=[], probe=None)
    probe = instrument(pred, vuln_build, binary=binary, source_file=source_file)
    verdicts = [
        confirm(
            probe,
            inp,
            sandbox=sandbox,
            vector=vector,
            extra_argv=extra_argv,
            timeout=timeout,
        )
        for inp in candidate_inputs
    ]
    return PredicateRun(predicate=pred, verdicts=verdicts, probe=probe)
