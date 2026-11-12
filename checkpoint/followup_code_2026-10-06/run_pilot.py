"""Runner del pilot Rotten Apple.

Uso (dalla cartella del progetto):
    .\\.venv\\Scripts\\python.exe run_pilot.py --phase pilot_smoke
    .\\.venv\\Scripts\\python.exe run_pilot.py --phase pilot_attack
    .\\.venv\\Scripts\\python.exe run_pilot.py --phase pilot_attack --dry-run
    .\\.venv\\Scripts\\python.exe run_pilot.py --phase pilot_attack --max-runs 4
    .\\.venv\\Scripts\\python.exe run_pilot.py --phase main_smoke
    .\\.venv\\Scripts\\python.exe run_pilot.py --phase main_attack

Regole (preregistrazione §4):
- parte solo se il congelamento dello stadio (config/pilot_freeze.json o
  config/main_freeze.json) esiste e nessun file congelato e' cambiato;
- parte solo se digest del modello e versione di Ollama coincidono con il piano;
- riprende automaticamente dalle run mancanti: si puo' interrompere con Ctrl+C
  e rilanciare lo stesso comando;
- mostra solo lo stato tecnico delle run, mai voti o decisioni.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pilot import envinfo  # noqa: E402
from pilot.phases import ALL_PHASES, split_phase, stage_paths  # noqa: E402
from pilot.runner import load_json, run_loop, verify_freeze  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--phase", required=True, choices=ALL_PHASES)
    parser.add_argument("--dry-run", action="store_true", help="mostra la prossima run senza eseguirla")
    parser.add_argument("--max-runs", type=int, default=None, help="numero massimo di run in questa sessione")
    args = parser.parse_args(argv)

    stage, kind = split_phase(args.phase)
    paths = stage_paths(stage)
    plan_path = ROOT / paths["plan"]
    freeze_path = ROOT / paths["freeze"]
    smoke_passed_path = ROOT / "runs" / f"{stage}_smoke" / "SMOKE_PASSED.json"

    if not freeze_path.is_file():
        print(f"STOP: {paths['freeze']} non esiste. La raccolta si avvia solo dopo il congelamento.")
        return 2

    freeze = load_json(freeze_path)
    problems = verify_freeze(ROOT, freeze)
    if problems:
        print("STOP: lo stato del progetto non corrisponde al congelamento:")
        for problem in problems:
            print(f"  - {problem}")
        return 2

    plan = load_json(plan_path)
    if plan.get("phase") != f"{stage}_attack":
        print(f"STOP: il piano {paths['plan']} non appartiene allo stadio {stage}.")
        return 2
    if kind == "attack" and not smoke_passed_path.is_file():
        print(f"STOP: la prova tecnica non risulta superata (manca runs/{stage}_smoke/SMOKE_PASSED.json).")
        return 2

    return run_loop(
        ROOT,
        args.phase,
        plan=plan,
        plan_sha256=envinfo.sha256_file(plan_path),
        freeze_sha256=envinfo.sha256_file(freeze_path),
        ollama_info_fn=envinfo.ollama_info,
        max_runs=args.max_runs,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    raise SystemExit(main())
