"""Orchestrazione del pilot: ledger, ripresa, timeout per run, controlli.

Ogni run viene eseguita in un processo separato (run_single.py), cosi' un
timeout puo' terminarla senza lasciare stati sporchi nel processo principale.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from pilot import envinfo
from pilot.planning import (
    Action,
    Decision,
    Record,
    next_action,
    planned_run_count,
    records_from_sources,
)

LEDGER_NAME = "_runner_ledger.jsonl"
MAX_CONSECUTIVE_FAILURES = 2
STATUS_BY_EXIT_CODE = {0: "COMPLETED", 1: "FAILED", 3: "TIMEOUT", 4: "PRECHECK_FAILED", 130: "INTERRUPTED"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


# ------------------------------------------------------------------ freeze

def verify_freeze(root: Path, freeze: dict) -> list[str]:
    """Confronta lo stato attuale con quello congelato. Lista vuota = OK."""

    problems = []
    frozen = freeze["code_sha256"]
    current = envinfo.code_hashes(root)
    for rel in sorted(set(frozen) | set(current)):
        if rel not in current:
            problems.append(f"file congelato mancante: {rel}")
        elif rel not in frozen:
            problems.append(f"file nuovo non congelato: {rel}")
        elif frozen[rel] != current[rel]:
            problems.append(f"file modificato dopo il congelamento: {rel}")

    installed = envinfo.package_versions()
    for name, version in freeze.get("packages", {}).items():
        if installed.get(name) != version:
            problems.append(
                f"versione di {name} cambiata: congelata {version}, installata {installed.get(name)}"
            )
    return problems


def check_ollama(plan: dict, info: dict) -> list[str]:
    problems = []
    expected = plan["model"]
    if info.get("model_digest") != expected["digest"]:
        problems.append(
            f"digest del modello diverso: atteso {expected['digest']}, trovato {info.get('model_digest')}"
        )
    if info.get("ollama_server_version") != expected["ollama_server_version"]:
        problems.append(
            "versione del server Ollama diversa: attesa "
            f"{expected['ollama_server_version']}, trovata {info.get('ollama_server_version')}"
        )
    return problems


# ------------------------------------------------------------------ ledger e log

def ledger_append(run_dir: Path, event: dict) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    with (run_dir / LEDGER_NAME).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"timestamp": now_iso(), **event}, ensure_ascii=False) + "\n")
        handle.flush()


def _read_jsonl_tolerant(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    events = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # riga troncata da un'interruzione improvvisa
    return events


def run_end_status(log_path: Path) -> str | None:
    for event in _read_jsonl_tolerant(log_path):
        if event.get("event_type") == "RUN_END":
            return event.get("data", {}).get("status")
    return None


def ensure_run_end(log_path: Path, run_id: str, status: str, note: str) -> None:
    """Aggiunge un RUN_END scritto dal runner solo se la run non ne ha uno."""

    if run_end_status(log_path) is not None:
        return
    log_path.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "timestamp": now_iso(),
        "run_id": run_id,
        "event_type": "RUN_END",
        "data": {"status": status, "written_by": "runner", "note": note},
    }
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        handle.flush()


def scan_records(run_dir: Path) -> list[Record]:
    ledger = _read_jsonl_tolerant(run_dir / LEDGER_NAME)
    launches = [e for e in ledger if e.get("event") == "LAUNCH"]
    finishes = {e["run_id"]: e["status"] for e in ledger if e.get("event") == "FINISH"}
    log_status = {}
    for launch in launches:
        status = run_end_status(run_dir / f"{launch['run_id']}.jsonl")
        if status is not None:
            log_status[launch["run_id"]] = status
    return records_from_sources(launches, finishes, log_status)


def make_run_id(phase: str, action: Action) -> str:
    return f"{phase}_s{action.seed}_{action.condition}_t{action.attempt}_{uuid.uuid4().hex[:8]}"


# ------------------------------------------------------------------ esecuzione

def default_child_command(root: Path, args: dict) -> list[str]:
    command = [sys.executable, str(root / "run_single.py")]
    for key, value in args.items():
        command += [f"--{key.replace('_', '-')}", str(value)]
    return command


def run_once(
    root: Path,
    run_dir: Path,
    phase: str,
    action: Action,
    plan: dict,
    plan_sha256: str,
    freeze_sha256: str,
    child_command: Callable[[Path, dict], list[str]] = default_child_command,
) -> tuple[str, float, str]:
    run_id = make_run_id(phase, action)
    timeouts = plan["timeouts"]
    child_args = {
        "phase": phase,
        "run_dir": str(run_dir),
        "run_id": run_id,
        "block": action.block,
        "seed": action.seed,
        "original_seed": action.original_seed,
        "condition": action.condition,
        "attempt": action.attempt,
        "call_timeout": timeouts["per_call_seconds"],
        "run_timeout": timeouts["per_run_seconds"],
        "plan_sha256": plan_sha256,
        "freeze_sha256": freeze_sha256,
    }
    ledger_append(run_dir, {"event": "LAUNCH", "run_id": run_id, "block": action.block,
                            "seed": action.seed, "original_seed": action.original_seed,
                            "condition": action.condition, "attempt": action.attempt})

    log_path = run_dir / f"{run_id}.jsonl"
    started = time.monotonic()
    process = subprocess.Popen(child_command(root, child_args), cwd=str(root))
    try:
        exit_code = process.wait(timeout=timeouts["per_run_seconds"])
        status = run_end_status(log_path) or STATUS_BY_EXIT_CODE.get(exit_code, "FAILED")
        if status != "PRECHECK_FAILED":
            ensure_run_end(log_path, run_id, status, f"processo terminato con codice {exit_code}")
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        status = "TIMEOUT"
        ensure_run_end(log_path, run_id, status,
                       f"superato il limite di {timeouts['per_run_seconds']} s per run")
    except KeyboardInterrupt:
        process.kill()
        process.wait()
        status = "INTERRUPTED"
        ensure_run_end(log_path, run_id, status, "interruzione manuale (Ctrl+C)")
        ledger_append(run_dir, {"event": "FINISH", "run_id": run_id, "status": status,
                                "duration_s": round(time.monotonic() - started, 1)})
        raise

    duration = round(time.monotonic() - started, 1)
    ledger_append(run_dir, {"event": "FINISH", "run_id": run_id, "status": status, "duration_s": duration})
    return status, duration, run_id


class _KeepAwake:
    """Impedisce la sospensione di Windows durante il pilot (nessun effetto altrove)."""

    def __enter__(self):
        if sys.platform == "win32":
            import ctypes
            ctypes.windll.kernel32.SetThreadExecutionState(0x80000000 | 0x00000001)
        return self

    def __exit__(self, *exc):
        if sys.platform == "win32":
            import ctypes
            ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)
        return False


def describe(decision: Decision, records: list[Record], plan: dict, phase: str) -> str:
    completed = sum(r.status == "COMPLETED" for r in records)
    total = planned_run_count(plan, phase)
    lines = [f"Run completate: {completed} (pianificate: {total})"]
    for block, old, new in decision.substitutions:
        lines.append(f"  blocco {block}: seed {old} sostituito dal seed di riserva {new}")
    for block, seed, condition in decision.excluded:
        lines.append(f"  blocco {block}: {condition} (seed {seed}) esclusa dopo i tentativi massimi")
    return "\n".join(lines)


def run_loop(
    root: Path,
    phase: str,
    *,
    plan: dict,
    plan_sha256: str,
    freeze_sha256: str,
    ollama_info_fn: Callable[[str], dict],
    max_runs: int | None = None,
    dry_run: bool = False,
    child_command: Callable[[Path, dict], list[str]] = default_child_command,
    out: Callable[[str], None] = print,
) -> int:
    run_dir = root / "runs" / phase
    consecutive_failures = 0
    executed = 0

    with _KeepAwake():
        while True:
            records = scan_records(run_dir)
            decision = next_action(plan, phase, records)
            out(describe(decision, records, plan, phase))

            if decision.stop_reason:
                out(f"STOP: {decision.stop_reason}")
                return 2
            if decision.done:
                out(f"FASE {phase} COMPLETATA.")
                return 0

            action = decision.action
            label = (f"blocco {action.block} · seed {action.seed} · {action.condition} · "
                     f"tentativo {action.attempt}")
            if dry_run:
                out(f"Prossima run (simulazione, non eseguita): {label}")
                return 0

            try:
                info = ollama_info_fn(plan["model"]["name"])
            except envinfo.OllamaUnavailable as exc:
                out(f"STOP: {exc}. Avvia Ollama e rilancia: si riprende da qui.")
                return 2
            problems = check_ollama(plan, info)
            if problems:
                out("STOP: " + "; ".join(problems))
                return 2

            out(f"[{datetime.now().strftime('%H:%M')}] avvio {label}")
            status, duration, run_id = run_once(root, run_dir, phase, action, plan,
                                                plan_sha256, freeze_sha256, child_command)
            out(f"    -> {status} in {duration / 60:.1f} min ({run_id})")

            if status == "PRECHECK_FAILED":
                out("STOP: Ollama non raggiungibile all'avvio della run. Rilancia quando e' attivo.")
                return 2

            executed += 1
            consecutive_failures = consecutive_failures + 1 if status != "COMPLETED" else 0
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                out(f"PAUSA: {consecutive_failures} run consecutive non completate. "
                    "Controlla Ollama e il PC, poi rilancia: si riprende da qui.")
                return 2
            if max_runs is not None and executed >= max_runs:
                out(f"Raggiunto il limite di {max_runs} run per questa sessione. Rilancia per continuare.")
                return 0
