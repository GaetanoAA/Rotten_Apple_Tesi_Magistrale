"""Congelamento del pilot (fase 4): scrive config/pilot_freeze.json.

Uso (dalla cartella del progetto, con Ollama acceso):
    .\\.venv\\Scripts\\python.exe tools\\freeze_pilot.py                 (pilot)
    .\\.venv\\Scripts\\python.exe tools\\freeze_pilot.py --stage main    (esperimento principale)

Controlla, in ordine, e si ferma al primo problema:
  1. il congelamento non esiste gia' e non ci sono dati del pilot;
  2. la preregistrazione e' firmata;
  3. tutti i test passano (pytest offline);
  4. digest del modello e versione di Ollama coincidono con il piano.
Poi registra lo SHA-256 di ogni file congelato, le versioni dei pacchetti
e le informazioni su Ollama. Non genera testo con il modello.

Solo se la prova tecnica rivela un guasto da correggere:
    .\\.venv\\Scripts\\python.exe tools\\freeze_pilot.py --supersede "motivo"
sposta (senza cancellarli) il congelamento precedente e i log della prova
tecnica in cartelle 'superseded'. Non e' mai permesso dopo l'inizio di
pilot_attack. La correzione va registrata come emendamento.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pilot import envinfo  # noqa: E402
from pilot.phases import STAGES, stage_paths  # noqa: E402
from pilot.runner import check_ollama, load_json  # noqa: E402

FREEZE_PATH = ROOT / "config" / "pilot_freeze.json"
PLAN_PATH = ROOT / "config" / "pilot_plan.json"
PREREG_PATH = ROOT / "documentazione" / "preregistrazione_pilot.md"
SIGNATURE = re.compile(r"^\|\s*Approvato da \(studente\)\s*\|\s*([^|_\s][^|]*)\|", re.MULTILINE)


class Stop(Exception):
    pass


def prereg_signed(text: str) -> bool:
    return bool(SIGNATURE.search(text))


def pilot_attack_has_data(root: Path, stage: str = "pilot") -> bool:
    return any((root / "runs" / f"{stage}_attack").glob("*.jsonl"))


def supersede(root: Path, reason: str, stage: str = "pilot") -> dict:
    if pilot_attack_has_data(root, stage):
        raise Stop(f"{stage}_attack ha gia' dei log: il congelamento non puo' piu' essere sostituito.")
    freeze_path = root / stage_paths(stage)["freeze"]
    if not freeze_path.is_file():
        raise Stop("non esiste un congelamento da sostituire.")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    old_sha = envinfo.sha256_file(freeze_path)
    target = root / "config" / "superseded"
    target.mkdir(parents=True, exist_ok=True)
    freeze_path.rename(target / f"{stage}_freeze_{stamp}.json")
    smoke = root / "runs" / f"{stage}_smoke"
    if smoke.is_dir():
        (root / "runs" / "superseded").mkdir(parents=True, exist_ok=True)
        smoke.rename(root / "runs" / "superseded" / f"{stage}_smoke_{stamp}")
    return {"previous_freeze_sha256": old_sha, "reason": reason, "archived_as": stamp}


def run_tests(root: Path) -> str:
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q"],
                          cwd=str(root), capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, timeout=1800)
    lines = [line for line in (proc.stdout + proc.stderr).splitlines() if line.strip()]
    last = lines[-1] if lines else "(nessun output)"
    if proc.returncode != 0:
        print(proc.stdout[-4000:])
        raise Stop(f"i test non passano: {last}")
    return last


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--supersede", metavar="MOTIVO")
    parser.add_argument("--stage", choices=tuple(STAGES), default="pilot")
    args = parser.parse_args(argv)
    paths = stage_paths(args.stage)
    freeze_path = ROOT / paths["freeze"]
    plan_path = ROOT / paths["plan"]
    prereg_path = ROOT / paths["prereg"]

    try:
        superseded = None
        if args.supersede:
            superseded = supersede(ROOT, args.supersede, args.stage)
            print(f"Congelamento precedente archiviato ({superseded['archived_as']}).")

        print("1. Stato del progetto")
        if freeze_path.is_file():
            raise Stop(f"{paths['freeze']} esiste gia'. Il congelamento si fa una sola volta.")
        if pilot_attack_has_data(ROOT, args.stage):
            raise Stop(f"runs/{args.stage}_attack contiene gia' dei log.")
        if not plan_path.is_file():
            raise Stop(f"{paths['plan']} non esiste.")
        if load_json(plan_path).get("phase") != f"{args.stage}_attack":
            raise Stop(f"il piano {paths['plan']} non appartiene allo stadio {args.stage}.")
        print("   OK")

        print("2. Firma della preregistrazione")
        if not prereg_signed(prereg_path.read_text(encoding="utf-8")):
            raise Stop("la riga 'Approvato da (studente)' della preregistrazione non e' compilata.")
        print("   OK")

        print("3. Test automatici (circa un minuto)")
        pytest_result = run_tests(ROOT)
        print(f"   {pytest_result}")

        print("4. Ollama e modello")
        plan = load_json(plan_path)
        info = envinfo.ollama_info(plan["model"]["name"])
        problems = check_ollama(plan, info)
        if problems:
            raise Stop("; ".join(problems))
        print(f"   OK: digest {info['model_digest'][:12]}..., Ollama {info['ollama_server_version']}")

        freeze = {
            "freeze_version": 1,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "stage": args.stage,
            "prereg_sha256": envinfo.sha256_file(prereg_path),
            "plan_sha256": envinfo.sha256_file(plan_path),
            "code_sha256": envinfo.code_hashes(ROOT),
            "packages": envinfo.package_versions(),
            "ollama": info,
            "pytest": pytest_result,
            "supersedes": superseded,
        }
        with freeze_path.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(freeze, ensure_ascii=False, indent=2) + "\n")

    except (Stop, envinfo.OllamaUnavailable) as exc:
        print(f"\nSTOP: {exc}")
        return 1

    print(f"\nCONGELAMENTO COMPLETATO: {len(freeze['code_sha256'])} file registrati.")
    print(f"SHA-256 di {paths['freeze']}: {envinfo.sha256_file(freeze_path)}")
    print(f"SHA-256 della preregistrazione:      {freeze['prereg_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
