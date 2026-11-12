import json
import os
from pathlib import Path
from datetime import datetime, timezone


# Cartella storica del dry run. Viene usata solo se ROTTEN_APPLE_RUN_DIR
# non e' impostata (comportamento legacy di experiment.py).
RESULTS_DIR = Path("results")

# Variabile d'ambiente impostata dal runner del pilot (runs/<phase>/).
RUN_DIR_ENV = "ROTTEN_APPLE_RUN_DIR"

# run_id il cui file e' gia' stato creato da questo processo.
_OPENED_RUN_IDS: set[str] = set()


def get_log_dir() -> Path:
    configured = os.environ.get(RUN_DIR_ENV)
    return Path(configured) if configured else RESULTS_DIR


def log_event(
    run_id: str,
    event_type: str,
    data: dict,
) -> None:

    log_dir = get_log_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{run_id}.jsonl"

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "event_type": event_type,
        "data": data,
    }

    # Il primo evento di una run crea il file in modo esclusivo:
    # se esiste gia' un file con lo stesso run_id, la scrittura fallisce
    # invece di aggiungere righe a una run diversa.
    mode = "a" if run_id in _OPENED_RUN_IDS else "x"

    with log_path.open(mode, encoding="utf-8") as file:
        file.write(
            json.dumps(event, ensure_ascii=False) + "\n"
        )
        file.flush()
        os.fsync(file.fileno())

    _OPENED_RUN_IDS.add(run_id)
