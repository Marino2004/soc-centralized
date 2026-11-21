import copy
from datetime import date

import pytest

from src.services.live_action_plan_service import (
    append_live_buckets,
    bucket_key,
    carry_over_live_buckets,
    empty_payload,
    find_new_buckets,
)
from src.utils.lock_utils import LockBusy, file_lock


def make_bucket(cve: str, agent: str) -> dict:
    return {
        "key": {"cve": cve, "agent": agent},
        "doc_count": 1,
        "details": {"hits": {"hits": [{"_source": {"agent": {"name": f"host-{agent}"}}}]}},
    }


def make_payload(*pairs) -> dict:
    payload = empty_payload(date(2026, 11, 19))
    payload["meta"].pop("baseline_pending")
    payload["aggregations"]["vulnerabilities_by_agent"]["buckets"] = [make_bucket(*p) for p in pairs]
    return payload


def keys(payload: dict) -> list:
    return [bucket_key(b) for b in payload["aggregations"]["vulnerabilities_by_agent"]["buckets"]]


def test_find_new_ignores_known_and_duplicates():
    payload = make_payload(("CVE-2026-0001", "001"))
    collected = [
        make_bucket("CVE-2026-0001", "001"),   # déjà connu
        make_bucket("CVE-2026-0002", "001"),   # nouveau
        make_bucket("CVE-2026-0002", "001"),   # doublon dans la collecte
        make_bucket("CVE-2026-0001", "002"),   # même CVE, autre agent => nouveau
        {"key": {"cve": None, "agent": "003"}},  # clé invalide
    ]
    new = find_new_buckets(payload, collected)
    assert [bucket_key(b) for b in new] == [("CVE-2026-0002", "001"), ("CVE-2026-0001", "002")]


def test_append_marks_live_and_updates_meta():
    payload = make_payload(("CVE-2026-0001", "001"))
    new = [make_bucket("CVE-2026-0002", "001")]
    append_live_buckets(payload, new, ["wazuh-alerts-4.x-2026.11.19*"])

    assert len(keys(payload)) == 2
    assert new[0]["live"] is True and "live_detected_at" in new[0]
    assert payload["meta"]["total_buckets"] == 2
    assert payload["meta"]["live"]["added_total"] == 1

    append_live_buckets(payload, [make_bucket("CVE-2026-0003", "001")], ["x"])
    assert payload["meta"]["live"]["added_total"] == 2
    assert payload["meta"]["live"]["last_added"] == 1


def test_sync_is_idempotent():
    payload = make_payload()
    collected = [make_bucket("CVE-2026-0002", "001")]
    append_live_buckets(payload, find_new_buckets(payload, collected), ["x"])
    assert find_new_buckets(payload, copy.deepcopy(collected)) == []


def test_daily_rerun_keeps_live_additions():
    previous = make_payload(("CVE-2026-0001", "001"))
    append_live_buckets(previous, [make_bucket("CVE-2026-0009", "007")], ["x"])

    baseline = make_payload(("CVE-2026-0001", "001"), ("CVE-2026-0005", "002"))
    assert carry_over_live_buckets(baseline, previous) == 1
    assert ("CVE-2026-0009", "007") in keys(baseline)
    assert baseline["meta"]["total_buckets"] == 3
    assert baseline["meta"]["live"]["added_total"] == 1


def test_carry_over_does_not_duplicate_when_baseline_has_it():
    previous = make_payload()
    append_live_buckets(previous, [make_bucket("CVE-2026-0009", "007")], ["x"])
    baseline = make_payload(("CVE-2026-0009", "007"))
    assert carry_over_live_buckets(baseline, previous) == 0
    assert keys(baseline) == [("CVE-2026-0009", "007")]


def test_lock_is_exclusive(tmp_path):
    lock = tmp_path / "x.lock"
    with file_lock(lock, timeout=0):
        with pytest.raises(LockBusy):
            with file_lock(lock, timeout=0):
                pass
    with file_lock(lock, timeout=0):   # libéré après sortie
        pass
