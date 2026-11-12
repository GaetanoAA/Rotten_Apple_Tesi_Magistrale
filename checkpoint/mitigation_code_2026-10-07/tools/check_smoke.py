"""Verifica della prova tecnica (pilot_smoke), preregistrazione §4.

Uso (dopo `run_pilot.py --phase pilot_smoke`):
    .\\.venv\\Scripts\\python.exe tools\\check_smoke.py                 (pilot)
    .\\.venv\\Scripts\\python.exe tools\\check_smoke.py --stage main    (esperimento principale)

La prova e' superata se per ognuna delle 4 condizioni esiste una run
COMPLETED, valida secondo §5 (punti 2-4), eseguita con il congelamento
attuale, con risposta grezza e tempi registrati per ogni chiamata.
In quel caso scrive runs/pilot_smoke/SMOKE_PASSED.json.

Mostra solo l'esito tecnico: mai voti o decisioni.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import analyze_attack as aa  # noqa: E402
import argparse  # noqa: E402

from pilot import envinfo  # noqa: E402
from pilot.phases import STAGES, stage_paths  # noqa: E402
from pilot.runner import load_json, verify_freeze  # noqa: E402


def evaluate_smoke(run_dir: Path, plan: dict, freeze: dict, freeze_sha256: str,
                   phase: str = "pilot_smoke") -> tuple[bool, list[dict]]:
    plan = {**plan, "_freeze_sha256": freeze_sha256}
    runs = aa.load_runs(run_dir, phase)
    results = []
    for condition in plan["smoke"]["conditions"]:
        candidates = [r for r in runs if r["start"].get("condition") == condition]
        best = None
        for run in candidates:
            problems = aa.check_run(run, plan)
            if run["start"].get("code_sha256") != freeze["code_sha256"]:
                problems.append("4: codice diverso da quello congelato")
            for agent, attempts in run["attempts"].items():
                for attempt in attempts:
                    if attempt.get("raw_output") is None or attempt.get("latency_s") is None:
                        problems.append(f"2: risposta grezza o tempo mancanti per {agent}")
            if not problems:
                best = run
                break
            results.append({"condition": condition, "file": run["file"], "ok": False, "problems": sorted(set(problems))})
        if best is not None:
            stamps = [e.get("timestamp") for e in best["events"] if e.get("timestamp")]
            minutes = None
            if len(stamps) >= 2:
                delta = datetime.fromisoformat(stamps[-1]) - datetime.fromisoformat(stamps[0])
                minutes = round(delta.total_seconds() / 60, 1)
            results.append({"condition": condition, "file": best["file"], "ok": True, "minutes": minutes,
                            "sha256": envinfo.sha256_file(run_dir / best["file"])})
        elif not candidates:
            results.append({"condition": condition, "file": None, "ok": False, "problems": ["nessuna run trovata"]})
    passed = all(any(r["ok"] for r in results if r["condition"] == c) for c in plan["smoke"]["conditions"])
    return passed, results


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=tuple(STAGES), default="pilot")
    args = parser.parse_args(argv)
    paths = stage_paths(args.stage)
    freeze_path = ROOT / paths["freeze"]
    run_dir = ROOT / "runs" / f"{args.stage}_smoke"
    if not freeze_path.is_file():
        print("STOP: congelamento assente.")
        return 1
    freeze = load_json(freeze_path)
    problems = verify_freeze(ROOT, freeze)
    if problems:
        print("STOP: il progetto non corrisponde al congelamento:\n  - " + "\n  - ".join(problems))
        return 1

    passed, results = evaluate_smoke(run_dir, load_json(ROOT / paths["plan"]),
                                     freeze, envinfo.sha256_file(freeze_path), f"{args.stage}_smoke")
    for r in results:
        if r["ok"]:
            print(f"[OK] {r['condition']}: {r['file']} ({r['minutes']} min)")
        else:
            print(f"[NO] {r['condition']}: {r['file']} -> {'; '.join(r['problems'])}")

    if not passed:
        print(f"\nPROVA TECNICA NON SUPERATA: non avviare {args.stage}_attack. Inviami questo output.")
        return 1

    marker = run_dir / "SMOKE_PASSED.json"
    with marker.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "passed_utc": datetime.now(timezone.utc).isoformat(),
            "freeze_sha256": envinfo.sha256_file(freeze_path),
            "runs": [r for r in results if r["ok"]],
        }, ensure_ascii=False, indent=2) + "\n")
    total = sum(r["minutes"] or 0 for r in results if r["ok"])
    print(f"\nPROVA TECNICA SUPERATA. Durata totale delle {sum(r['ok'] for r in results)} run: {total:.0f} min.")
    print(f"Scritto runs/{args.stage}_smoke/SMOKE_PASSED.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
