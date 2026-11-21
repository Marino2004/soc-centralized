import logging
import os
import tempfile
from datetime import date
from pathlib import Path
from typing import Optional

import json

from src.loaders import VulnerabilityTrackingLoader
from src.services.daily_action_plan_service import DailyActionPlanService
from src.services.live_action_plan_service import carry_over_live_buckets
from src.utils.date_utils import get_day_label
from src.utils.lock_utils import LOCK_NAME, file_lock
from src.utils.source_utils import vuln_source
from src.utils.storage_utils import fetch_dataset_json, publish_dataset

logger = logging.getLogger(__name__)

MINIO_BUCKET = os.environ.get("MINIO_BUCKET_DASHBOARD", "dashboard-data")
PIPELINE_NAME = "daily_action_plan"


def run_daily_action_plan_pipeline(
    indexer_client,
    base_dir: Path,
    collection_date: Optional[date] = None,
    index_override: Optional[str] = None,
    skip_publish: bool = False,
) -> str:
    collection_date = collection_date or date.today()
    daily_service = DailyActionPlanService(indexer_client=indexer_client)
    day_label = get_day_label(collection_date)
    indices_override = [index_override] if index_override else None

    if skip_publish:
        output_dir = base_dir / "local_output"
        output_dir.mkdir(parents=True, exist_ok=True)
        local_json_path = output_dir / f"data_{day_label}.json"

        daily_service.generate_data_json(
            collection_date,
            output_path=local_json_path,
            indices_override=indices_override,
        )
        print(f"[LOCAL] daily_action_plan écrit dans : {local_json_path}")
        return str(local_json_path)

    # Verrou partagé avec le job live : évite que les deux réécrivent data_<jour>.json en même temps.
    with file_lock(base_dir / "logs" / LOCK_NAME, timeout=300), \
            tempfile.TemporaryDirectory() as tmp_dir:
        local_json_path = Path(tmp_dir) / f"data_{day_label}.json"
        daily_service.generate_data_json(
            collection_date,
            output_path=local_json_path,
            indices_override=indices_override,
        )
        _guard_empty_inventory(local_json_path)
        if vuln_source() == "alerts":
            # En mode states, le JSON est un instantané complet : rien à reporter
            # (et reporter une vulnérabilité déjà corrigée serait une erreur).
            _carry_over_live(local_json_path, day_label)

        publish_dataset(
            local_path=local_json_path,
            bucket=MINIO_BUCKET,
            pipeline_name=PIPELINE_NAME,
            week_label=day_label,
        )
        print(
            f"Dataset publié : s3://{MINIO_BUCKET}/{PIPELINE_NAME}/latest.json "
            f"(archive data_{day_label}.json)"
        )

        try:
            loader = VulnerabilityTrackingLoader(data_json_path=local_json_path)
            nb_loaded = loader.load()
            print(f"Suivi vulnérabilités chargé en base : {nb_loaded} enregistrements ({day_label})")
        except Exception:
            logger.exception("Échec du chargement en base pour %s", local_json_path)

    return f"s3://{MINIO_BUCKET}/{PIPELINE_NAME}/latest.json"


def _guard_empty_inventory(local_json_path: Path) -> None:
    """
    Inventaire vide = très probablement une panne de lecture (le collecteur renvoie [] en
    repli). Publier et charger en base marquerait TOUTES les vulnérabilités comme disparues.
    """
    if vuln_source() != "states":
        return
    meta = json.loads(local_json_path.read_text(encoding="utf-8")).get("meta", {})
    if meta.get("total_buckets", 0) == 0:
        raise RuntimeError(
            "Inventaire wazuh-states-vulnerabilities vide : publication et chargement en base annulés."
        )


def _carry_over_live(local_json_path: Path, day_label: str) -> None:
    """
    Conserve les vulnérabilités ajoutées en cours de journée par le job live
    si data_<jour>.json existe déjà (re-run manuel, ou live passé avant le daily).
    En cas d'échec de lecture on continue : le prochain passage du job live
    ré-ajoute de lui-même ce qui manque (il est idempotent).
    """
    try:
        previous = fetch_dataset_json(MINIO_BUCKET, PIPELINE_NAME, day_label)
    except FileNotFoundError:
        return
    except Exception:
        logger.exception("Lecture de data_%s.json impossible, ajouts live non reportés", day_label)
        return

    baseline = json.loads(local_json_path.read_text(encoding="utf-8"))
    carried = carry_over_live_buckets(baseline, previous)
    if carried:
        local_json_path.write_text(
            json.dumps(baseline, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
        )
        print(f"{carried} vulnérabilité(s) ajoutée(s) en live reportée(s) dans data_{day_label}.json")