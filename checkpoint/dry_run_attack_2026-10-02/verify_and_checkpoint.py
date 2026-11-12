"""Verifica e congelamento del dry run Rotten Apple (fase 1 del percorso verso il pilot).

Cosa fa, in ordine (si ferma al primo errore):
  1. confronta SHA-256 e dimensione di ogni file con MANIFEST.json;
  2. segnala file non previsti nel progetto;
  3. registra l'ambiente (Python, pip freeze, versione e digest del modello Ollama,
     hardware). NON genera testo: usa solo `ollama --version/list/show` e le API
     di metadati /api/version e /api/tags;
  4. esegue pytest offline (atteso: 11 passed);
  5. riesegue lo script di analisi congelato e confronta l'output con quello atteso;
  6. riesegue l'audit indipendente e lo confronta con quello atteso;
  7. crea lo ZIP del checkpoint fuori dalla cartella del progetto e ne calcola l'hash;
  8. imposta i log di results/ in sola lettura.

Non modifica codice, configurazioni o log (salvo l'attributo di sola lettura al punto 8).
Non legge .env.

Uso (dalla cartella del progetto, in PowerShell):
    .\\.venv\\Scripts\\python.exe checkpoint\\dry_run_attack_2026-10-02\\verify_and_checkpoint.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

CK = Path(__file__).resolve().parent
ROOT = CK.parents[1]
MODEL = "llama3.1:8b-instruct-q4_K_M"
ZIP_NAME = "RottenApple_checkpoint_dry_run_attack_2026-10-02.zip"
SKIP_DIRS = {".venv", "__pycache__", ".pytest_cache", "checkpoint", ".git"}
SKIP_FILES = {".env"}

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


class Stop(Exception):
    pass


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def step(title: str) -> None:
    print(f"\n=== {title}")


def run(cmd: list[str], timeout: int = 120, env: dict | None = None) -> tuple[int, str]:
    try:
        p = subprocess.run(
            cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, env=env,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, f"comando non trovato: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"timeout dopo {timeout}s: {' '.join(cmd)}"


def http_json(url: str):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def verify_files(manifest: dict) -> None:
    step("1. Verifica hash dei file rispetto al manifest")
    bad = []
    for rel, meta in manifest["files"].items():
        p = ROOT / rel
        if not p.is_file():
            bad.append(f"MANCANTE  {rel}")
            continue
        if p.stat().st_size != meta["bytes"] or sha256(p) != meta["sha256"]:
            bad.append(f"DIVERSO   {rel}")
    if bad:
        print("\n".join(bad))
        raise Stop("Alcuni file non corrispondono al manifest: NON procedere, inviami questo output.")
    print(f"OK: {len(manifest['files'])} file identici al manifest.")


def check_untracked(manifest: dict, allow_extra: bool) -> None:
    step("2. Ricerca di file non previsti")
    tracked = set(manifest["files"])
    extra = []
    for p in ROOT.rglob("*"):
        rel = p.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in rel.parts) or p.name in SKIP_FILES or not p.is_file():
            continue
        if rel.as_posix() not in tracked:
            extra.append(rel.as_posix())
    if extra:
        print("File non presenti nel manifest:\n  " + "\n  ".join(sorted(extra)))
        if not allow_extra:
            raise Stop("File non previsti: inviameli o rilancia con --allow-extra se sono innocui.")
    else:
        print("OK: nessun file non previsto.")


def capture_environment(require_digest: bool) -> dict:
    step("3. Registrazione dell'ambiente (nessuna generazione di testo)")
    env_dir = CK / "environment"
    env_dir.mkdir(exist_ok=True)
    info: dict = {}

    (env_dir / "python.txt").write_text(
        f"sys.version: {sys.version}\nexecutable: {sys.executable}\nplatform: {platform.platform()}\n",
        encoding="utf-8",
    )
    _, freeze = run([sys.executable, "-m", "pip", "freeze"])
    (env_dir / "pip_freeze_utf8.txt").write_text(freeze, encoding="utf-8")

    for name, cmd in {
        "ollama_version.txt": ["ollama", "--version"],
        "ollama_list.txt": ["ollama", "list"],
        "ollama_show.txt": ["ollama", "show", MODEL],
    }.items():
        code, out = run(cmd)
        (env_dir / name).write_text(f"$ {' '.join(cmd)}\n(exit {code})\n{out}", encoding="utf-8")

    digest = None
    try:
        version = http_json("http://127.0.0.1:11434/api/version")
        tags = http_json("http://127.0.0.1:11434/api/tags")
        (env_dir / "ollama_api_version.json").write_text(json.dumps(version, indent=2), encoding="utf-8")
        (env_dir / "ollama_api_tags.json").write_text(json.dumps(tags, indent=2), encoding="utf-8")
        for m in tags.get("models", []):
            if m.get("name") == MODEL or m.get("model") == MODEL:
                digest = m.get("digest")
                info["model_modified_at"] = m.get("modified_at")
        info["ollama_server_version"] = version.get("version")
    except Exception as exc:  # server non avviato
        (env_dir / "ollama_api_error.txt").write_text(repr(exc), encoding="utf-8")

    info["model_digest"] = digest
    (env_dir / "model_digest.txt").write_text(
        f"model: {MODEL}\ndigest: {digest}\nmodified_at: {info.get('model_modified_at')}\n"
        "nota: rilevato a posteriori il giorno del checkpoint, non al momento del dry run.\n",
        encoding="utf-8",
    )

    hw_cmd = (
        "Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors | Format-List; "
        "Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion,AdapterRAM | Format-List; "
        "Get-CimInstance Win32_ComputerSystem | Select-Object TotalPhysicalMemory | Format-List; "
        "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | Format-List"
    )
    _, hw = run(["powershell", "-NoProfile", "-Command", hw_cmd]) if os.name == "nt" else (0, platform.uname().__repr__())
    if shutil.which("nvidia-smi"):
        _, smi = run(["nvidia-smi"])
        hw += "\n--- nvidia-smi ---\n" + smi
    (env_dir / "hardware.txt").write_text(hw, encoding="utf-8")
    ollama_env = {k: v for k, v in os.environ.items() if k.upper().startswith("OLLAMA")}
    (env_dir / "ollama_env.json").write_text(json.dumps(ollama_env, indent=2), encoding="utf-8")

    print(f"Versione server Ollama: {info.get('ollama_server_version')}")
    print(f"Digest del modello:     {digest}")
    if digest is None and require_digest:
        raise Stop(
            "Digest del modello non rilevato. Avvia Ollama (solo il server/app, nessun prompt) "
            "e rilancia questo script. In alternativa: --allow-missing-digest (sconsigliato)."
        )
    return info


def run_pytest(expected: str) -> str:
    step("4. pytest offline")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    code, out = run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider"], timeout=600, env=env)
    (CK / "pytest_output.txt").write_text(out, encoding="utf-8")
    last = [line for line in out.strip().splitlines() if line.strip()][-1:] or ["(nessun output)"]
    print(last[0])
    if code != 0 or expected not in out:
        raise Stop(f"pytest non ha restituito '{expected}'. Output salvato in pytest_output.txt.")
    return last[0]


def compare_json(cmd: list[str], expected, label: str, out_name: str) -> None:
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    code, out = run(cmd, timeout=300, env=env)
    (CK / out_name).write_text(out, encoding="utf-8")
    if code != 0:
        raise Stop(f"{label}: errore di esecuzione (vedi {out_name}).")
    try:
        got = json.loads(out)
    except json.JSONDecodeError as exc:
        raise Stop(f"{label}: output non JSON ({exc}).")
    if got != json.loads(json.dumps(expected)):
        raise Stop(f"{label}: output DIVERSO da quello atteso (vedi {out_name}).")
    print(f"OK: {label} identico a quello atteso.")


def make_zip(manifest: dict) -> tuple[Path, str]:
    step("7. Creazione dello ZIP del checkpoint")
    mpath = CK / "MANIFEST.json"
    (CK / "MANIFEST.json.sha256").write_text(f"{sha256(mpath)}  MANIFEST.json\n", encoding="utf-8")
    zpath = ROOT.parent / ZIP_NAME
    prefix = ROOT.name
    with zipfile.ZipFile(zpath, "x", compression=zipfile.ZIP_DEFLATED) as z:
        for rel in sorted(manifest["files"]):
            z.write(ROOT / rel, f"{prefix}/{rel}")
        for p in sorted(CK.rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts:
                z.write(p, f"{prefix}/{p.relative_to(ROOT).as_posix()}")
    digest = sha256(zpath)
    (ROOT.parent / f"{ZIP_NAME}.sha256").write_text(f"{digest}  {ZIP_NAME}\n", encoding="utf-8")
    (CK / "ZIP_SHA256.txt").write_text(f"{digest}  {ZIP_NAME}\n", encoding="utf-8")
    print(f"ZIP:     {zpath}")
    print(f"SHA-256: {digest}")
    return zpath, digest


def set_readonly(manifest: dict) -> int:
    step("8. Log di results/ in sola lettura")
    n = 0
    for rel in manifest["files"]:
        if rel.startswith("results/"):
            os.chmod(ROOT / rel, stat.S_IREAD)
            n += 1
    print(f"OK: {n} log impostati in sola lettura.")
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--allow-extra", action="store_true")
    ap.add_argument("--allow-missing-digest", action="store_true")
    args = ap.parse_args()

    manifest = json.loads((CK / "MANIFEST.json").read_text(encoding="utf-8"))
    if (ROOT.parent / ZIP_NAME).exists():
        print(f"Lo ZIP {ZIP_NAME} esiste gia': checkpoint gia' creato, nulla da fare.")
        return 0
    report: dict = {"checkpoint_id": manifest["checkpoint_id"]}
    try:
        verify_files(manifest)
        check_untracked(manifest, args.allow_extra)
        report["environment"] = capture_environment(not args.allow_missing_digest)
        report["pytest"] = run_pytest(manifest["expected_pytest"])
        step("5. Script di analisi congelato")
        compare_json([sys.executable, "analyze_dry_run_attack.py", "--format", "json"],
                     manifest["dry_run_attack"]["expected_analyzer_rows"],
                     "analyze_dry_run_attack.py", "analysis_local_output.json")
        step("6. Audit indipendente")
        compare_json([sys.executable, str(CK / "audit_dry_run.py"), "--results-dir", "results"],
                     manifest["expected_audit_report"], "audit_dry_run.py", "audit_local_output.json")
        report["status"] = "VERIFIED"
        (CK / "verification_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        _, zdigest = make_zip(manifest)
        report["zip_sha256"] = zdigest
        report["readonly_logs"] = set_readonly(manifest)
        (CK / "verification_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    except Stop as exc:
        report["status"] = f"STOPPED: {exc}"
        (CK / "verification_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nSTOP: {exc}")
        return 1

    print("\nFASE 1 COMPLETATA. Inviami l'output completo di questa finestra.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
