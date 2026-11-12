"""Appendice esplorativa: condizione C5 (etichetta verificata), identificativi neutri."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

import analyze_attack as aa
import run_single
from config.attack import build_sec_7421
from config.model import MODEL_CONFIG
from config.visibility import VISIBILITY_BY_CONDITION
from pilot import envinfo
from pilot.phases import ALL_PHASES, stage_paths
from pilot.planning import planned_run_count
from tools import check_smoke

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PLANS = {name: json.loads((PROJECT_ROOT / "config" / f"{name}_plan.json").read_text(encoding="utf-8"))
         for name in ("pilot", "main", "variant", "appendix")}
APPENDIX_PLAN = PLANS["appendix"]
C1, C4, C5 = "C1-ROTTEN-ISO", "C4-ROTTEN-MULTI", "C5-ROTTEN-VERIFIED"


def test_appendix_phases_and_files():
    assert {"appendix_smoke", "appendix_attack"} <= set(ALL_PHASES)
    assert stage_paths("appendix")["prereg"] == "documentazione/preregistrazione_appendice.md"
    assert "config/appendix_plan.json" in envinfo.FROZEN_PATTERNS


def test_appendix_plan_follows_declared_rules():
    assert APPENDIX_PLAN["phase"] == "appendix_attack"
    assert APPENDIX_PLAN["model"] == PLANS["variant"]["model"]
    seeds = random.Random(20261012).sample(range(10000, 100000), 51)
    assert [b["seed"] for b in APPENDIX_PLAN["blocks"]] == seeds[:40]
    assert APPENDIX_PLAN["reserve_seeds"] == seeds[40:50]
    assert APPENDIX_PLAN["smoke"]["seed"] == seeds[50]
    rng = random.Random(20261013)
    for block in APPENDIX_PLAN["blocks"]:
        expected = [C1, C4, C5]
        rng.shuffle(expected)
        assert block["order"] == expected


def test_appendix_seeds_disjoint_from_previous_phases():
    used = set(PLANS["pilot"]["seed_generation"]["excluded_seeds"])
    for name in ("pilot", "main", "variant"):
        plan = PLANS[name]
        used |= {b["seed"] for b in plan["blocks"]} | set(plan["reserve_seeds"]) | {plan["smoke"]["seed"]}
    new = {b["seed"] for b in APPENDIX_PLAN["blocks"]} | set(APPENDIX_PLAN["reserve_seeds"]) | {APPENDIX_PLAN["smoke"]["seed"]}
    assert len(new) == 51 and not new & used


def test_appendix_planning_and_visibility():
    assert planned_run_count(APPENDIX_PLAN, "appendix_attack") == 120
    assert planned_run_count(APPENDIX_PLAN, "appendix_smoke") == 3
    assert VISIBILITY_BY_CONDITION[C5] == VISIBILITY_BY_CONDITION[C4]


def test_attestation_defaults_unchanged():
    sec = build_sec_7421(run_id="R", pair_id="P")
    assert sec["object_id"] == "mem://R/A/attestation/SEC-7421"
    assert sec["integrity_label"] == "unverified_internal"
    neutral = build_sec_7421(run_id="R", pair_id="P", namespace="run", integrity_label="verified_internal")
    assert neutral["object_id"] == "mem://run/A/attestation/SEC-7421"
    assert {k: v for k, v in neutral.items() if k not in ("object_id", "integrity_label")} == \
        {k: v for k, v in sec.items() if k not in ("object_id", "integrity_label")}


def _run_smoke(tmp_path, monkeypatch, fake_model, fake_ollama_info, phase, plan):
    monkeypatch.setenv("ROTTEN_APPLE_RUN_DIR", str(tmp_path))
    monkeypatch.setenv("ROTTEN_APPLE_CALL_TIMEOUT_S", "30")
    monkeypatch.setitem(MODEL_CONFIG, "seed", 42)
    fake_model()
    seed = str(plan["smoke"]["seed"])
    for n, condition in enumerate(plan["smoke"]["conditions"]):
        argv = ["--phase", phase, "--run-dir", str(tmp_path), "--run-id", f"{phase}_{n}_{condition}",
                "--block", "0", "--seed", seed, "--original-seed", seed,
                "--condition", condition, "--attempt", "1", "--call-timeout", "30", "--run-timeout", "5400",
                "--plan-sha256", "p" * 64, "--freeze-sha256", "f" * 64]
        assert run_single.main(argv, env_info_fn=fake_ollama_info) == 0
    return {r["start"]["condition"]: r for r in aa.load_runs(tmp_path, phase)}


def test_appendix_neutral_ids_and_label(tmp_path, monkeypatch, fake_model, fake_ollama_info):
    runs = _run_smoke(tmp_path, monkeypatch, fake_model, fake_ollama_info, "appendix_smoke", APPENDIX_PLAN)
    assert set(runs) == {C1, C4, C5}
    for condition, run in runs.items():
        assert aa.check_run(run, None) == [], condition
        for agent, inp in run["inputs"].items():
            prompt = inp.get("initial_prompt") or ""
            assert run["start"]["run_id"] not in prompt
            assert "ROTTEN" not in prompt and "CLEAN" not in prompt and "appendix" not in prompt
    for agent in ("B", "C", "D"):
        p4 = runs[C4]["inputs"][agent]["initial_prompt"]
        p5 = runs[C5]["inputs"][agent]["initial_prompt"]
        assert "integrity_label: unverified_internal" in p4
        assert "integrity_label: verified_internal" in p5
        if agent == "B":
            assert p4.replace("unverified_internal", "verified_internal") == p5
    freeze = {"code_sha256": envinfo.code_hashes(PROJECT_ROOT)}
    passed, results = check_smoke.evaluate_smoke(tmp_path, APPENDIX_PLAN, freeze, "f" * 64, "appendix_smoke")
    assert passed, results


def test_previous_phases_keep_run_id_in_ids(tmp_path, monkeypatch, fake_model, fake_ollama_info):
    runs = _run_smoke(tmp_path, monkeypatch, fake_model, fake_ollama_info, "variant_smoke", PLANS["variant"])
    b_prompt = runs[C4]["inputs"]["B"]["initial_prompt"]
    assert runs[C4]["start"]["run_id"] in b_prompt
    assert "integrity_label: unverified_internal" in b_prompt


@pytest.mark.skipif(not (PROJECT_ROOT / "runs" / "variant_attack").is_dir(), reason="log assenti")
def test_appendix_analysis_handles_missing_c5():
    runs = aa.load_runs(PROJECT_ROOT / "runs" / "variant_attack", "variant_attack")
    report = aa.analyze_appendix(runs, "appendix_attack", PLANS["variant"])
    assert report["quality"]["all_ok"] is False
