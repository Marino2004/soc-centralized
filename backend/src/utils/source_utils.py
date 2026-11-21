import os

DEFAULT_STATES_INDEX_PATTERN = "wazuh-states-vulnerabilities-*"


def vuln_source() -> str:
    """
    Source des vulnérabilités du pipeline daily_action_plan :
      - "states" (défaut) : inventaire courant, index wazuh-states-vulnerabilities-*
      - "alerts"          : alertes vulnerability-detector, index wazuh-alerts-4.x-<date>
    """
    value = os.getenv("WAZUH_VULN_SOURCE", "states").strip().lower()
    return value if value in ("states", "alerts") else "states"


def states_index_pattern() -> str:
    return os.getenv("WAZUH_INDEXER_INDEX_PATTERN_STATES", DEFAULT_STATES_INDEX_PATTERN)
