from typing import Optional

from .collector import DailyActionPlanCollector

DESCRIPTION_MAX = 140

_SOURCE_FIELDS = [
    "agent.name",
    "package.name",
    "package.version",
    "vulnerability.severity",
    "vulnerability.score.base",
    "vulnerability.scanner.condition",
    "vulnerability.scanner.source",
    "vulnerability.description",
    "vulnerability.detected_at",
]


def _clean(d: dict) -> dict:
    """Retire les clés à None (le loader attend une valeur ou une clé absente)."""
    return {k: v for k, v in d.items() if v is not None}


def to_alert_shape(source: dict) -> dict:
    """
    Convertit un document de wazuh-states-vulnerabilities-* vers la forme `_source`
    d'une alerte vulnerability-detector, que le loader et le front savent déjà lire.
    """
    vuln = source.get("vulnerability", {})
    pkg = source.get("package", {})
    scanner = vuln.get("scanner", {})
    score = vuln.get("score", {}).get("base")

    description = (vuln.get("description") or "").strip()
    if len(description) > DESCRIPTION_MAX:
        description = description[: DESCRIPTION_MAX - 1].rstrip() + "…"

    out = _clean({
        "severity": vuln.get("severity") or "Unknown",
        "package": _clean({
            "name": pkg.get("name"),
            "version": pkg.get("version"),
            "condition": scanner.get("condition"),
        }),
        "scanner": _clean({"source": scanner.get("source")}),
        "title": description or None,
        "detected_at": vuln.get("detected_at"),
    })
    # Wazuh renvoie -1 quand le score est inconnu ou « under evaluation » : on l'omet
    # (le loader retombe alors sur 0.0 et le front affiche « — »).
    if isinstance(score, (int, float)) and score >= 0:
        out["cvss"] = {"cvss3": {"base_score": score}}

    return {
        "agent": _clean({"name": source.get("agent", {}).get("name")}),
        "data": {"vulnerability": out},
    }


class StatesVulnerabilityCollector(DailyActionPlanCollector):
    """
    Lit l'inventaire courant (wazuh-states-vulnerabilities-*), dédupliqué par
    (CVE, agent), et renvoie des buckets au même format que le collecteur d'alertes.
    """

    def _build_query(self, after_key: Optional[dict], page_size: int) -> dict:
        composite: dict = {
            "size": page_size,
            "sources": [
                {"cve": {"terms": {"field": "vulnerability.id"}}},
                {"agent": {"terms": {"field": "agent.id"}}},
            ],
        }
        if after_key:
            composite["after"] = after_key
        return {
            "size": 0,
            "track_total_hits": True,
            "timeout": "30s",
            "query": {"match_all": {}},
            "aggs": {
                "vulnerabilities_by_agent": {
                    "composite": composite,
                    "aggs": {
                        "details": {
                            "top_hits": {
                                "size": 1,
                                "sort": [{"vulnerability.score.base": {"order": "desc"}}],
                                "_source": _SOURCE_FIELDS,
                            }
                        }
                    },
                }
            },
        }

    def _normalize_bucket(self, bucket: dict) -> dict:
        for hit in bucket.get("details", {}).get("hits", {}).get("hits", []):
            hit["_source"] = to_alert_shape(hit.get("_source", {}))
        return bucket
