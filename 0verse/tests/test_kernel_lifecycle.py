from __future__ import annotations

from zeroverse.kernel_lifecycle import (
    LifecycleCampaignResult,
    RelationKind,
    extract_changed_symbols,
    extract_lifecycle_tokens,
    plan_lifecycle_campaign,
)

_GHL_PATCH = """\
diff --git a/drivers/hid/hid-sony.c b/drivers/hid/hid-sony.c
@@
-static void ghl_remove(struct hid_device *hdev)
+static void ghl_remove(struct hid_device *hdev)
 {
+    usb_kill_urb(ghl->ghl_urb);
+    del_timer_sync(&ghl->ghl_poke_timer);
+    usb_free_urb(ghl->ghl_urb);
 }
"""


def test_extracts_lifecycle_tokens_and_changed_symbols() -> None:
    assert extract_lifecycle_tokens(_GHL_PATCH) == ("timer", "urb", "free")
    assert extract_changed_symbols(_GHL_PATCH) == ("ghl_remove",)


def test_plans_curated_teardown_candidates_without_execution() -> None:
    plan = plan_lifecycle_campaign(_GHL_PATCH)
    assert plan.schema_version == "0verse.kernel-lifecycle/v1"
    assert not plan.executable
    assert plan.candidates
    assert any(
        candidate.relation.relation is RelationKind.SAME_TEARDOWN
        for candidate in plan.candidates
    )
    assert all(
        "patched-control-clean" in candidate.required_evidence
        for candidate in plan.candidates
    )


def test_empty_patch_is_rejected() -> None:
    try:
        plan_lifecycle_campaign(" ")
    except ValueError as exc:
        assert str(exc) == "patch_text must not be empty"
    else:
        raise AssertionError("empty patch must fail")


def test_result_needs_kcov_kasan_and_evidence_to_confirm() -> None:
    result = LifecycleCampaignResult(
        candidate_id="candidate",
        direct_lifecycle_executed=True,
        kcov_reached=True,
        manager_admitted=False,
        kasan_differential_confirmed=True,
        evidence_digest="a" * 64,
    )
    assert result.confirmed
    assert not LifecycleCampaignResult(
        candidate_id="candidate",
        direct_lifecycle_executed=True,
        kcov_reached=True,
        manager_admitted=True,
        kasan_differential_confirmed=True,
    ).confirmed
