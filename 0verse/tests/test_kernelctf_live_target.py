import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts/kernelctf/audit-live-target.py"
SPEC = importlib.util.spec_from_file_location("kernelctf_live_target", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

compare = MODULE.compare
parse_banner = MODULE.parse_banner


BANNER = (
    "\nServer time: 2026-07-13T00:13:28Z\n\n"
    "Current targets:\n"
    "  - lts-6.12.94 | Release date: 2026-07-10 12:00Z | "
    "Slot is taken by exp544 (probably not eligible anymore)\n\n"
    'Select a target (or type "deprecated" to see deprecated targets):\n'
)


def test_parse_taken_target() -> None:
    assert parse_banner(BANNER) == {
        "release": "lts-6.12.94",
        "release_date": "2026-07-10 12:00Z",
        "slot_status": "taken",
        "slot_holder": "exp544",
    }


def test_parse_free_target() -> None:
    live = parse_banner(BANNER.replace("taken by exp544", "free"))
    assert live["slot_status"] == "free"
    assert live["slot_holder"] == ""


def test_compare_detects_rotation_and_free_slot() -> None:
    snapshot = {"release": "lts-6.12.94", "slot_status": "taken", "slot_holder": "exp544"}
    live = {
        "release": "lts-6.12.95",
        "slot_status": "free",
        "slot_holder": "",
        "release_date": "now",
    }
    assert compare(snapshot, live) == [
        "release: snapshot='lts-6.12.94' live='lts-6.12.95'",
        "slot_status: snapshot='taken' live='free'",
        "slot_holder: snapshot='exp544' live=''",
    ]
