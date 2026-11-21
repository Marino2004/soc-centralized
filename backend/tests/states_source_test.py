import json
from datetime import datetime, timezone
from pathlib import Path

from src.collectors.daily_action_plan import StatesVulnerabilityCollector
from src.collectors.daily_action_plan.states_collector import to_alert_shape
from src.loaders import VulnerabilityTrackingLoader

# Document réel de wazuh-states-vulnerabilities-nessus-scanner (Wazuh 4.14.9)
STATES_DOC = {
    "agent": {"id": "001", "name": "debian-linux-dell", "type": "Wazuh", "version": "v4.14.9"},
    "package": {"name": "idna", "type": "pypi", "version": "3.6"},
    "vulnerability": {
        "description": "Internationalized Domain Names in Applications (IDNA) for Python provides support for "
                       "Internationalized Domain Names in Applications (IDNA) and Unicode IDNA Compatibility Processing.",
        "detected_at": "2026-11-19T09:01:26.106Z",
        "id": "CVE-2026-45409",
        "scanner": {"condition": "Package less than 3.15", "source": "Open Source Vulnerabilities", "vendor": "Wazuh"},
        "score": {"base": 5.3, "version": "3.1"},
        "severity": "Medium",
    },
}


class FakeIndexer:
    def __init__(self, pages):
        self.pages, self.bodies = pages, []

    def search(self, index, body):
        self.bodies.append((index, body))
        return self.pages[len(self.bodies) - 1]


def bucket(cve, agent, doc):
    return {"key": {"cve": cve, "agent": agent}, "doc_count": 1, "details": {"hits": {"hits": [{"_source": doc}]}}}


def test_to_alert_shape_matches_what_front_and_loader_read():
    out = to_alert_shape(STATES_DOC)
    vuln = out["data"]["vulnerability"]
    assert out["agent"]["name"] == "debian-linux-dell"
    assert vuln["severity"] == "Medium"
    assert vuln["cvss"]["cvss3"]["base_score"] == 5.3
    assert vuln["package"] == {"name": "idna", "version": "3.6", "condition": "Package less than 3.15"}
    assert len(vuln["title"]) <= 140 and vuln["title"].endswith("…")


def test_missing_score_and_condition_do_not_break():
    doc = {"agent": {"name": "a"}, "package": {"name": "x"}, "vulnerability": {"id": "CVE-2026-1", "severity": "Low"}}
    vuln = to_alert_shape(doc)["data"]["vulnerability"]
    assert "cvss" not in vuln and "condition" not in vuln["package"]


def test_collector_paginates_and_normalizes():
    page1 = {"aggregations": {"vulnerabilities_by_agent": {
        "buckets": [bucket("CVE-2026-45409", "001", STATES_DOC)], "after_key": {"cve": "CVE-2026-45409", "agent": "001"}}}}
    page2 = {"aggregations": {"vulnerabilities_by_agent": {"buckets": [bucket("CVE-2026-1111", "002", STATES_DOC)]}}}
    indexer = FakeIndexer([page1, page2])
    buckets = StatesVulnerabilityCollector(indexer).get_vulnerabilities_by_agent(["wazuh-states-vulnerabilities-*"])

    assert len(buckets) == 2
    assert buckets[0]["details"]["hits"]["hits"][0]["_source"]["data"]["vulnerability"]["severity"] == "Medium"
    assert "after" not in indexer.bodies[0][1]["aggs"]["vulnerabilities_by_agent"]["composite"]
    assert indexer.bodies[1][1]["aggs"]["vulnerabilities_by_agent"]["composite"]["after"] == {"cve": "CVE-2026-45409", "agent": "001"}


def test_loader_accepts_normalized_states_bucket():
    raw_bucket = bucket("CVE-2026-45409", "001", to_alert_shape(STATES_DOC))
    raw = {"meta": {"date_to": "2026-11-19T23:59:59Z"},
           "aggregations": {"vulnerabilities_by_agent": {"buckets": [raw_bucket]}}}
    records = VulnerabilityTrackingLoader()._extract_records(raw)
    assert len(records) == 1
    r = records[0]
    assert (r.cve_id, r.agent_name, r.severity, r.package, r.cvss, r.fix_version) == (
        "CVE-2026-45409", "debian-linux-dell", "Medium", "idna", 5.3, "Package less than 3.15")


def test_negative_score_is_omitted_and_record_still_loads():
    doc = {**STATES_DOC, "vulnerability": {**STATES_DOC["vulnerability"], "score": {"base": -1.0}}}
    shaped = to_alert_shape(doc)
    assert "cvss" not in shaped["data"]["vulnerability"]

    raw = {"meta": {"date_to": "2026-11-19T23:59:59Z"},
           "aggregations": {"vulnerabilities_by_agent": {"buckets": [bucket("CVE-2025-40065", "001", shaped)]}}}
    records = VulnerabilityTrackingLoader()._extract_records(raw)
    assert len(records) == 1 and records[0].cvss == 0.0
