import json
import logging
import os
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

from src.loaders import VulnerabilityTrackingLoader
from src.services.live_action_plan_service import (
    LiveActionPlanService,
    append_live_buckets,
    empty_payload,
)
from src.utils.date_utils import get_day_label
from src.utils.lock_utils import LOCK_NAME, LockBusy, file_lock
from src.utils.storage_utils import fetch_dataset_json, publish_dataset, upload_json

logger = logging.getLogger(__name__)

MINIO_BUCKET = os.environ.get("MINIO_BUCKET_DASHBOARD", "dashboard-data")
PIPELINE_NAME = "daily_action_plan"


def _dump(payload: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )


def run_live_action_plan_pipeline(
    indexer_client,
    base_dir: Path,
    collection_date: Optional[date] = None,
    index_override: Optional[str] = None,
    skip_publish: bool = False,
) -> str:
    """
    Ajoute au JSON du jour (data_<jour>.json + latest.json) les nouvelles
    vulnérabilités apparues dans l'index d'alertes du jour depuis le dernier passage.
    N'enlève jamais rien : les disparitions restent gérées par le run daily.
    """
    collection_date = collection_date or date.today()
    day_label = get_day_label(collection_date)
    service = LiveActionPlanService(indexer_client=indexer_client)
    indices_override = [index_override] if index_override else None

    if skip_publish:
        local_path = base_dir / "local_output" / f"data_{day_label}.json"
        if local_path.exists():
            payload = json.loads(local_path.read_text(encoding="utf-8"))
        else:
            payload = empty_payload(collection_date)
        new_buckets, indices = service.detect_new(payload, collection_date, indices_override)
        if new_buckets:
            append_live_buckets(payload, new_buckets, indices)
            _dump(payload, local_path)
        print(f"[LOCAL] live : {len(new_buckets)} nouvelle(s) vulnérabilité(s) -> {local_path}")
        return str(local_path)

    try:
        with file_lock(base_dir / "logs" / LOCK_NAME, timeout=0):
            return _sync(service, collection_date, day_label, indices_override)
    except LockBusy:
        return "ignoré : un run daily ou live est déjà en cours (prochain passage du timer)"


def _sync(
    service: LiveActionPlanService,
    collection_date: date,
    day_label: str,
    indices_override: Optional[list[str]],
) -> str:
    try:
        payload = fetch_dataset_json(MINIO_BUCKET, PIPELINE_NAME, day_label)
    except FileNotFoundError:
        payload = empty_payload(collection_date)
    # Toute autre erreur de lecture remonte : on n'écrase jamais le JSON du jour à l'aveugle.

    if service.source == "states" and payload["meta"].get("baseline_pending"):
        # Inventaire complet : sans le run daily du jour, tout serait « nouveau ».
        # Le prochain passage après le daily comparera correctement.
        return f"en attente du run daily du jour (data_{day_label}.json absent)"

    new_buckets, indices = service.detect_new(payload, collection_date, indices_override)
    if not new_buckets:
        return f"aucune nouvelle vulnérabilité ({day_label})"

    append_live_buckets(payload, new_buckets, indices)

    with tempfile.TemporaryDirectory() as tmp_dir:
        local_path = Path(tmp_dir) / f"data_{day_label}.json"
        _dump(payload, local_path)

        if payload["meta"].get("baseline_pending"):
            # Pas encore de run daily aujourd'hui : on ne touche pas à latest.json
            # (il porte encore le plan complet de la veille).
            upload_json(local_path, MINIO_BUCKET, f"{PIPELINE_NAME}/data_{day_label}.json")
        else:
            publish_dataset(
                local_path=local_path,
                bucket=MINIO_BUCKET,
                pipeline_name=PIPELINE_NAME,
                week_label=day_label,
            )

        try:
            nb = VulnerabilityTrackingLoader().load_buckets(
                new_buckets, detected_at=datetime.now(timezone.utc)
            )
            logger.info("Live : %d enregistrement(s) chargés en base", nb)
        except Exception:
            # Le JSON est déjà à jour ; la base sera rattrapée par le prochain run daily.
            logger.exception("Live : échec du chargement en base (%d buckets)", len(new_buckets))

    return f"{len(new_buckets)} nouvelle(s) vulnérabilité(s) ajoutée(s) à data_{day_label}.json"
