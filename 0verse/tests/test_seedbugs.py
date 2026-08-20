"""XNU/IOKit fold-in (#18): the IOKit user-client seed-bug-class + kext target hook."""

from __future__ import annotations

from zeroverse.seedbugs import (
    IOKIT_USER_CLIENT,
    prime_hypotheses,
    seed_for_target,
)

_DISPATCH = (
    "IOReturn externalMethod(uint sel, IOExternalMethodArguments *args)\n"
    "{\n"
    "  void *buf = IOMalloc(args->structureInputSize);\n"
    "  copyin(args->structureInput, buf, args->structureInputSize);\n"
    "  return sel;\n"
    "}\n"
)
_CHECKED = (
    "IOReturn externalMethod(uint sel, IOExternalMethodArguments *args)\n"
    "{\n"
    "  if (args->scalarInputCount >= 4) return kIOReturnBadArgument;\n"
    "  IOMalloc(args->structureInputSize);\n"
    "  return sel;\n"
    "}\n"
)
_UNRELATED = "int add(int a, int b) { return a + b; }\n"


def test_seed_matches_dispatch_with_sink() -> None:
    ok, disp, sink = IOKIT_USER_CLIENT.matches(_DISPATCH)
    assert ok
    assert disp == "externalMethod"
    assert sink in ("IOMalloc", "copyin")


def test_seed_does_not_match_plain_function() -> None:
    ok, _disp, _sink = IOKIT_USER_CLIENT.matches(_UNRELATED)
    assert not ok


def test_prime_hypotheses_emits_iokit_findings() -> None:
    primed = prime_hypotheses(
        IOKIT_USER_CLIENT, {"externalMethod": _DISPATCH, "add": _UNRELATED}
    )
    assert len(primed) == 1
    f = primed[0]
    assert f.function == "externalMethod"
    assert f.origin == "seed:iokit.user-client.dispatch"
    assert f.source.startswith("iokit:")


def test_unbounded_candidate_ranks_before_checked() -> None:
    primed = prime_hypotheses(
        IOKIT_USER_CLIENT, {"checked": _CHECKED, "unbounded": _DISPATCH}
    )
    # the bound-less dispatch (more suspicious) sorts first
    assert primed[0].function == "unbounded"


def test_seed_for_target_macho_kext() -> None:
    # decompiled C with an IOKit dispatch token primes the IOKit seed class.
    seed = seed_for_target("Mach-O", "KEXT_BUNDLE", {"externalMethod": _DISPATCH})
    assert seed is IOKIT_USER_CLIENT
    # ELF never primes it.
    assert seed_for_target("ELF", "EXEC", {"externalMethod": _DISPATCH}) is None
    # a kext with no bodies yet still primes on format/kind alone.
    assert seed_for_target("Mach-O", "KEXT_BUNDLE", None) is IOKIT_USER_CLIENT
