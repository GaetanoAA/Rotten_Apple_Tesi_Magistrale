"""Strumenti della fase 4: firma, sostituzione del congelamento, verifica della prova tecnica."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import run_single
from config.model import MODEL_CONFIG
from pilot import envinfo
from tools import check_smoke, freeze_pilot

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PLAN = json.loads((PROJECT_ROOT / "config" / "pilot_plan.json").read_text(encoding="utf-8"))


def test_signature_detection():
    assert freeze_pilot.prereg_signed("| Approvato da (studente) | Mario Rossi |\n")
    assert not freeze_pilot.prereg_signed("| Approvato da (studente) | ______________________ |\n")


def test_supersede_archives_without_deleting_and_is_blocked_after_pilot_data(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "pilot_freeze.json").write_text("{}", encoding="utf-8")
    (tmp_path / "runs" / "pilot_smoke").mkdir(parents=True)
    (tmp_path / "runs" / "pilot_smoke" / "x.jsonl").write_text("{}\n", encoding="utf-8")
    info = freeze_pilot.supersede(tmp_path, "test")
    assert not (tmp_path / "config" / "pilot_freeze.json").exists()
    assert list((tmp_path / "config" / "superseded").glob("pilot_freeze_*.json"))
    assert list((tmp_path / "runs" / "superseded").glob("pilot_smoke_*/x.jsonl"))
    assert info["reason"] == "test"

    (tmp_path / "config" / "pilot_freeze.json").write_text("{}", encoding="utf-8")
    (tmp_path / "runs" / "pilot_attack").mkdir(parents=True)
    (tmp_path / "runs" / "pilot_attack" / "y.jsonl").write_text("{}\n", encoding="utf-8")
    with pytest.raises(freeze_pilot.Stop):
        freeze_pilot.supersede(tmp_path, "test")


@pytest.fixture
def smoke_dir(tmp_path, monkeypatch, fake_model, fake_ollama_info):
    monkeypatch.setenv("ROTTEN_APPLE_RUN_DIR", str(tmp_path))
    monkeypatch.setenv("ROTTEN_APPLE_CALL_TIMEOUT_S", "30")
    monkeypatch.setitem(MODEL_CONFIG, "seed", 42)
    fake_model()
    for n, condition in enumerate(PLAN["smoke"]["conditions"]):
        argv = ["--phase", "pilot_smoke", "--run-dir", str(tmp_path), "--run-id", f"smoke_{n}",
                "--block", "0", "--seed", str(PLAN["smoke"]["seed"]), "--original-seed", str(PLAN["smoke"]["seed"]),
                "--condition", condition, "--attempt", "1", "--call-timeout", "30", "--run-timeout", "5400",
                "--plan-sha256", "p" * 64, "--freeze-sha256", "f" * 64]
        assert run_single.main(argv, env_info_fn=fake_ollama_info) == 0
    return tmp_path


def test_smoke_check_passes_for_valid_runs(smoke_dir):
    freeze = {"code_sha256": envinfo.code_hashes(PROJECT_ROOT)}
    passed, results = check_smoke.evaluate_smoke(smoke_dir, PLAN, freeze, "f" * 64)
    assert passed, results
    assert len(results) == 4 and all(r["ok"] for r in results)


def test_smoke_check_rejects_runs_from_another_freeze(smoke_dir):
    freeze = {"code_sha256": envinfo.code_hashes(PROJECT_ROOT)}
    passed, results = check_smoke.evaluate_smoke(smoke_dir, PLAN, freeze, "0" * 64)
    assert not passed
    assert all("congelamento" in " ".join(r["problems"]) for r in results)


def test_smoke_check_rejects_missing_raw_output(smoke_dir):
    path = smoke_dir / "smoke_0.jsonl"
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    for event in events:
        if event["event_type"] == "AGENT_ATTEMPT":
            event["data"]["raw_output"] = None
            break
    path.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    freeze = {"code_sha256": envinfo.code_hashes(PROJECT_ROOT)}
    passed, results = check_smoke.evaluate_smoke(smoke_dir, PLAN, freeze, "f" * 64)
    assert not passed
