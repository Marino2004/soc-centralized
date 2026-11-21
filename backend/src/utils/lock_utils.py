import fcntl
import time
from contextlib import contextmanager
from pathlib import Path

LOCK_NAME = "daily_action_plan.lock"


class LockBusy(RuntimeError):
    """Le verrou est déjà détenu par un autre process (daily ou live)."""


@contextmanager
def file_lock(path: Path, timeout: float = 0.0, poll: float = 1.0):
    """
    Verrou exclusif (flock) partagé entre conteneurs via le volume ./logs.

    timeout=0   -> non bloquant : lève LockBusy immédiatement si occupé (job live).
    timeout>0   -> attend jusqu'à `timeout` secondes puis lève LockBusy (job daily).
    Le verrou est libéré par le noyau si le process meurt : pas de lock orphelin.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "a+")
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise LockBusy(f"verrou occupé : {path}")
                time.sleep(poll)
        yield
    finally:
        try:
            fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            handle.close()
