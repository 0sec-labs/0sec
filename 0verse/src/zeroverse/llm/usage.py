"""Provider-neutral LLM call/token accounting.

An eval harness has to tell four states apart, and a bare token count cannot:

* **measured** — the model was called and the provider reported token usage.
* **unreported** — the model was called but the provider hands back no usage
  object (the ChatGPT-OAuth Responses wire is unmetered, so it may omit it).
  Tokens are *unknown*, not zero.
* **all-calls-failed** — every call raised. The lane is dead.
* **no-calls** — the model was never invoked at all.

Before this module, only ``CodexOAuthLLM`` tracked anything, and only on a
successful ``response.completed`` that carried a ``usage`` object.
``AnthropicLLM``/``OpenAILLM`` tracked nothing and discarded the SDK's
``resp.usage`` outright, so a harness doing
``getattr(llm, "total_usage", {})`` silently got ``{}`` -> 0 tokens / $0.00.
That collapses all four states above onto the same output. It matters because
``agent.TriageAgent.triage`` deliberately swallows *every* backend exception
(it degrades to a structural hypothesis rather than crashing a long run), so an
LLM lane that never once reached the model otherwise leaves no trace in the
result: findings still appear, the ``reason`` stage is still recorded, and the
token count still reads 0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Accounting states, worst-to-best. Exposed so callers can render them without
# re-deriving the vocabulary.
STATUS_NO_CALLS = "no-calls"
STATUS_ALL_FAILED = "all-calls-failed"
STATUS_UNREPORTED = "unreported"
STATUS_MEASURED = "measured"


@dataclass
class UsageTracker:
    """Per-backend ledger of LLM calls and (when the provider reports them) tokens."""

    calls_ok: int = 0
    calls_failed: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    # Did the provider EVER hand back a usage object? False + calls_ok > 0 means
    # the token numbers below are unknown, not zero.
    usage_reported: bool = False
    last_usage: dict[str, int] = field(default_factory=dict)

    def record(
        self, input_tokens: int, output_tokens: int, *, reported: bool = True
    ) -> None:
        """Record one response's token usage. ``reported=False`` marks a response
        the provider returned with no usage object (tokens stay unknown)."""
        if not reported:
            return
        self.usage_reported = True
        self.last_usage = {"input_tokens": input_tokens, "output_tokens": output_tokens}
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens

    def note_ok(self) -> None:
        self.calls_ok += 1

    def note_failed(self) -> None:
        self.calls_failed += 1

    @property
    def total_usage(self) -> dict[str, int]:
        return {"input_tokens": self.input_tokens, "output_tokens": self.output_tokens}

    @property
    def status(self) -> str:
        if self.calls_ok:
            return STATUS_MEASURED if self.usage_reported else STATUS_UNREPORTED
        return STATUS_ALL_FAILED if self.calls_failed else STATUS_NO_CALLS

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "calls_ok": self.calls_ok,
            "calls_failed": self.calls_failed,
            "usage_reported": self.usage_reported,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        }


class TrackedLLM:
    """Mixin giving a backend a ``UsageTracker`` plus the historical
    ``total_usage`` / ``last_usage`` attributes the eval harnesses already read."""

    def __init__(self) -> None:
        self.usage = UsageTracker()

    @property
    def total_usage(self) -> dict[str, int]:
        return self.usage.total_usage

    @property
    def last_usage(self) -> dict[str, int]:
        return dict(self.usage.last_usage)


def record_sdk_usage(
    tracker: UsageTracker, usage_obj: Any, input_field: str, output_field: str
) -> None:
    """Record a provider SDK's usage object. A missing object or missing fields
    are recorded as *unreported* rather than as zero tokens."""
    if usage_obj is None:
        tracker.record(0, 0, reported=False)
        return
    inp = getattr(usage_obj, input_field, None)
    out = getattr(usage_obj, output_field, None)
    if inp is None and out is None:
        tracker.record(0, 0, reported=False)
        return
    tracker.record(int(inp or 0), int(out or 0))


def merge_accounting(blocks: list[dict[str, Any]]) -> dict[str, Any]:
    """Combine per-scan accounting blocks into one. The status is re-derived from
    the summed counters, so a run whose every call failed cannot average itself
    back into looking healthy."""
    agg = UsageTracker()
    for b in blocks:
        agg.calls_ok += int(b.get("calls_ok", 0) or 0)
        agg.calls_failed += int(b.get("calls_failed", 0) or 0)
        agg.input_tokens += int(b.get("input_tokens", 0) or 0)
        agg.output_tokens += int(b.get("output_tokens", 0) or 0)
        agg.usage_reported = agg.usage_reported or bool(b.get("usage_reported"))
    return agg.to_dict()
