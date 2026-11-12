"""Hash dei file congelati, informazioni su Ollama e versioni software.

Nessuna funzione di questo modulo genera testo con il modello: le uniche
chiamate a Ollama sono alle API di metadati /api/version e /api/tags.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import sys
import urllib.request
from pathlib import Path

OLLAMA_HOST = "http://127.0.0.1:11434"

# File il cui contenuto viene congelato prima del pilot (fase 4).
# Il runner rifiuta di partire se uno di questi file cambia.
FROZEN_PATTERNS = (
    "config/*.py",
    "core/*.py",
    "agents/*.py",
    "pilot/*.py",
    "tools/*.py",
    "tests/*.py",
    "run_single.py",
    "run_pilot.py",
    "analyze_attack.py",
    "pytest.ini",
    "requirements-lock.txt",
    "config/pilot_plan.json",
    "config/main_plan.json",
    "config/variant_plan.json",
    "documentazione/preregistrazione_pilot.md",
    "documentazione/preregistrazione_principale.md",
    "documentazione/preregistrazione_variante.md",
)

TRACKED_PACKAGES = (
    "langgraph",
    "langchain-core",
    "langchain-ollama",
    "ollama",
    "pydantic",
)


class OllamaUnavailable(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def frozen_files(root: Path) -> list[str]:
    root = Path(root)
    found: set[str] = set()
    for pattern in FROZEN_PATTERNS:
        for path in root.glob(pattern):
            if path.is_file() and "__pycache__" not in path.parts:
                found.add(path.relative_to(root).as_posix())
    return sorted(found)


def code_hashes(root: Path) -> dict[str, str]:
    root = Path(root)
    return {rel: sha256_file(root / rel) for rel in frozen_files(root)}


def package_versions() -> dict[str, str]:
    versions = {}
    for name in TRACKED_PACKAGES:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = "unknown"
    return versions


def runtime_info() -> dict:
    return {
        "python_version": sys.version,
        "platform": platform.platform(),
        "packages": package_versions(),
    }


def _get_json(url: str, timeout: float = 10.0):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def ollama_info(model: str, host: str = OLLAMA_HOST) -> dict:
    try:
        version = _get_json(f"{host}/api/version")
        tags = _get_json(f"{host}/api/tags")
    except Exception as exc:
        raise OllamaUnavailable(
            f"Ollama non raggiungibile su {host}: {exc!r}"
        ) from exc

    digest = None
    modified_at = None
    for entry in tags.get("models", []):
        if entry.get("name") == model or entry.get("model") == model:
            digest = entry.get("digest")
            modified_at = entry.get("modified_at")

    return {
        "ollama_server_version": version.get("version"),
        "model_digest": digest,
        "model_modified_at": modified_at,
    }
