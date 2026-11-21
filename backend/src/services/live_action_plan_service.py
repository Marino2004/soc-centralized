import logging
import os
from datetime import date, datetime, timezone
from typing import Optional

from src.clients.wazuh_indexer import WazuhIndexerClient
from src.collectors.daily_action_plan import DailyActionPlanCollector, StatesVulnerabilityCollector
from src.utils.date_utils import DEFAULT_DAILY_INDEX_PATTERN, get_day_label
from src.utils.source_utils import states_index_pattern, vuln_source

logger = logging.getLogger(__name__)

BucketKey = tuple[Optional[str], Optional[str]]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _buckets(payload: dict) -> list[dict]:
    return payload["aggregations"]["vulnerabilities_by_agent"]["buckets"]


def bucket_key(bucket: dict) -> BucketKey:
    """Clé d'unicité d'un bucket : (CVE, id agent) — même clé que la composite agg."""
    key = bucket.get("key", {})
    return key.get("cve"), key.get("agent")


def empty_payload(collection_date: date) -> dict:
    """
    JSON du jour créé par le job live quand le baseline journalier n'existe pas
    encore. `baseline_pending` est écrasé par le run daily (voir carry_over_live_buckets).
    """
    day_end = datetime.combine(collection_date, datetime.max.time()).replace(microsecond=0)
    return {
        "meta": {
            "generated_at": _utc_now_iso(),
            "collection_date": get_day_label(collection_date),
            "date_to": day_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_indices": [],
            "total_buckets": 0,
            "baseline_pending": True,
        },
        "aggregations": {"vulnerabilities_by_agent": {"buckets": []}},
    }


def find_new_buckets(payload: dict, collected: list[dict]) -> list[dict]:
    """Buckets collectés dont la clé (CVE, agent) n'est pas encore dans le JSON du jour."""
    known = {bucket_key(b) for b in _buckets(payload)}
    new: list[dict] = []
    for bucket in collected:
        key = bucket_key(bucket)
        if None in key or key in known:
            continue
        known.add(key)
        new.append(bucket)
    return new


def append_live_buckets(payload: dict, new_buckets: list[dict], live_indices: list[str]) -> dict:
    """Ajoute les nouveaux buckets (marqués `live`) et met à jour meta."""
    now = _utc_now_iso()
    for bucket in new_buckets:
        bucket["live"] = True
        bucket["live_detected_at"] = now

    _buckets(payload).extend(new_buckets)

    meta = payload["meta"]
    live = meta.setdefault("live", {})
    live["last_sync_at"] = now
    live["last_added"] = len(new_buckets)
    live["added_total"] = live.get("added_total", 0) + len(new_buckets)
    live["source_indices"] = live_indices
    meta["total_buckets"] = len(_buckets(payload))
    meta["generated_at"] = now
    return payload


def carry_over_live_buckets(baseline: dict, previous: dict) -> int:
    """
    Reporte dans `baseline` (JSON fraîchement généré par le run daily) les buckets
    `live` du JSON précédent du même jour, afin qu'un re-run daily n'écrase pas
    les ajouts faits en cours de journée. Retourne le nombre de buckets reportés.
    """
    known = {bucket_key(b) for b in _buckets(baseline)}
    carried = [
        b for b in _buckets(previous)
        if b.get("live") and bucket_key(b) not in known
    ]
    if not carried:
        return 0

    _buckets(baseline).extend(carried)
    baseline["meta"]["total_buckets"] = len(_buckets(baseline))
    previous_live = previous.get("meta", {}).get("live")
    if previous_live:
        baseline["meta"]["live"] = previous_live
    return len(carried)


class LiveActionPlanService:
    """
    Relit la source (inventaire `wazuh-states-vulnerabilities-*` par défaut, ou l'index
    d'alertes du jour si WAZUH_VULN_SOURCE=alerts) et en extrait les couples (CVE, agent)
    absents du JSON du jour. Sans état : relancé à l'identique, il ne produit rien de
    plus (idempotent).
    """

    def __init__(self, indexer_client: WazuhIndexerClient, index_pattern: str = None):
        self.source = vuln_source()
        collector_cls = (
            StatesVulnerabilityCollector if self.source == "states" else DailyActionPlanCollector
        )
        self._collector = collector_cls(indexer_client)
        self._index_pattern = index_pattern or os.getenv(
            "WAZUH_INDEXER_INDEX_PATTERN_DAILY", DEFAULT_DAILY_INDEX_PATTERN
        )

    def live_indices(self, collection_date: date) -> list[str]:
        if self.source == "states":
            return [states_index_pattern()]
        # Le '*' final évite une erreur 404 tant que l'index du jour n'existe pas
        # (début de journée, avant la première alerte).
        return [self._index_pattern.format(date=collection_date.strftime("%Y.%m.%d")) + "*"]

    def detect_new(
        self,
        payload: dict,
        collection_date: date,
        indices_override: Optional[list[str]] = None,
        page_size: int = 1000,
    ) -> tuple[list[dict], list[str]]:
        indices = indices_override or self.live_indices(collection_date)
        collected = self._collector.get_vulnerabilities_by_agent(indices, page_size=page_size)
        new_buckets = find_new_buckets(payload, collected)
        logger.info(
            "Live : %d bucket(s) lus sur %s, %d nouveau(x)",
            len(collected), ",".join(indices), len(new_buckets),
        )
        return new_buckets, indices
