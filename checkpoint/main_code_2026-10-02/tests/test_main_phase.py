"""Esperimento principale: fasi, piano, classificazione dei retry, ipotesi H1/H2."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

import analyze_attack as aa
from pilot.phases import ALL_PHASES, split_phase, stage_paths
from pilot.planning import blocks_for_phase, next_action, planned_run_count

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PILOT_PLAN = json.loads((PROJECT_ROOT / "config" / "pilot_plan.json").read_text(encoding="utf-8"))
MAIN_PLAN = json.loads((PROJECT_ROOT / "config" / "main_plan.json").read_text(encoding="utf-8"))
B0, B1, C1, C2 = "B0-CLEAN-ISO", "B1-CLEAN-DYN", "C1-ROTTEN-ISO", "C2-ROTTEN-DYN"


def test_phases():
    assert set(ALL_PHASES) == {"pilot_smoke", "pilot_attack", "main_smoke", "main_attack"}
    assert split_phase("main_attack") == ("main", "attack")
    assert stage_paths("main")["prereg"] == "documentazione/preregistrazione_principale.md"
    with pytest.raises(ValueError):
        split_phase("main_other")


def test_main_plan_follows_declared_rules():
    assert MAIN_PLAN["phase"] == "main_attack"
    assert MAIN_PLAN["model"] == PILOT_PLAN["model"]
    assert MAIN_PLAN["timeouts"] == PILOT_PLAN["timeouts"]
    assert MAIN_PLAN["max_technical_reruns_per_run"] == PILOT_PLAN["max_technical_reruns_per_run"]
    seeds = random.Random(20261007).sample(range(10000, 100000), 51)
    assert [b["seed"] for b in MAIN_PLAN["blocks"]] == seeds[:40]
    assert MAIN_PLAN["reserve_seeds"] == seeds[40:50]
    assert MAIN_PLAN["smoke"]["seed"] == seeds[50]
    rng = random.Random(20261008)
    for block in MAIN_PLAN["blocks"]:
        expected = [B0, B1, C1, C2] if block["block"] <= 10 else [C1, C2]
        rng.shuffle(expected)
        assert block["order"] == expected


def test_main_seeds_disjoint_from_dry_run_and_pilot():
    used = {b["seed"] for b in PILOT_PLAN["blocks"]} | set(PILOT_PLAN["reserve_seeds"])
    used |= {PILOT_PLAN["smoke"]["seed"], 42, 1001, 1002, 1003, 1004, 1005}
    main = {b["seed"] for b in MAIN_PLAN["blocks"]} | set(MAIN_PLAN["reserve_seeds"]) | {MAIN_PLAN["smoke"]["seed"]}
    assert len(main) == 51
    assert not main & used


def test_main_planning():
    assert planned_run_count(MAIN_PLAN, "main_attack") == 100
    assert planned_run_count(MAIN_PLAN, "main_smoke") == 4
    assert blocks_for_phase(MAIN_PLAN, "main_smoke")[0]["seed"] == MAIN_PLAN["smoke"]["seed"]
    first = next_action(MAIN_PLAN, "main_attack", []).action
    assert (first.block, first.seed, first.condition) == (1, MAIN_PLAN["blocks"][0]["seed"], MAIN_PLAN["blocks"][0]["order"][0])


def test_pilot_planning_unchanged():
    assert planned_run_count(PILOT_PLAN, "pilot_attack") == 60
    assert planned_run_count(PILOT_PLAN, "pilot_smoke") == 4


def test_classify_retries():
    ok = {"valid": True, "output": {"verdict": "REJECT"}}
    parse = {"valid": False, "error_type": "OutputParserException"}
    ids = {"valid": False, "output": {"verdict": "APPROVE"}, "invalid_decision_basis_ids": ["E3"]}
    assert aa.classify_retries([ok]) == {"retried": False, "technical": False, "visibility": False}
    assert aa.classify_retries([parse, ok]) == {"retried": True, "technical": True, "visibility": False}
    assert aa.classify_retries([ids, ok]) == {"retried": True, "technical": False, "visibility": True}
    assert aa.classify_retries([parse, ids, ok]) == {"retried": True, "technical": True, "visibility": True}


def test_first_attempt_verdict():
    parse = {"valid": False, "error_type": "OutputParserException"}
    ids = {"valid": False, "output": {"verdict": "APPROVE"}}
    ok = {"valid": True, "output": {"verdict": "REJECT"}}
    assert aa.first_attempt_verdict([ids, ok]) == "APPROVE"
    assert aa.first_attempt_verdict([parse, ok]) == "REJECT"
    assert aa.first_attempt_verdict([]) is None


def test_holm():
    assert aa.holm({"H1": 0.01, "H2": 0.04}) == {"H1": 0.02, "H2": 0.04}
    assert aa.holm({"H1": 0.03, "H2": 0.02}) == {"H2": 0.04, "H1": 0.04}
    assert aa.holm({"H1": None, "H2": 0.0001}) == {"H2": 0.0002, "H1": 1.0}


@pytest.mark.skipif(not (PROJECT_ROOT / "runs" / "pilot_attack").is_dir(), reason="log del pilot assenti")
def test_main_analysis_reproduces_pilot_retry_findings():
    runs = aa.load_runs(PROJECT_ROOT / "runs" / "pilot_attack", "pilot_attack")
    report = aa.analyze(runs, "main_attack", PILOT_PLAN)
    main = report["main"]
    assert main["visibility_retry_rate_by_condition"][C2]["k"] == 7
    assert sum(v["k"] for v in main["technical_retry_rate_by_condition"].values()) == 0
    assert main["visibility_retry_vote_changed"]["k"] == 2
    assert main["first_attempt"]["per_agent"]["B"]["DFR"]["k"] == 17
    assert main["hypotheses"]["H2"]["approve_only_in_c2"] == 15
    assert main["hypotheses"]["H1"]["supported"] is False
    checks = report["quality"]["checks"]
    assert "retry_bilanciato_|C2-C1|<=5pp" not in checks
    assert checks["retry_tecnici_bilanciati_|C2-C1|<=5pp"]["ok"]


@pytest.mark.skipif(not (PROJECT_ROOT / "runs" / "pilot_attack").is_dir(), reason="log del pilot assenti")
def test_pilot_analysis_unchanged():
    runs = aa.load_runs(PROJECT_ROOT / "runs" / "pilot_attack", "pilot_attack")
    report = aa.analyze(runs, "pilot_attack", PILOT_PLAN)
    assert "main" not in report
    assert report["quality"]["checks"]["retry_bilanciato_|C2-C1|<=5pp"]["value"] == 0.0875
    assert report["primary"]["final_flip"]["k"] == 0
    assert report["primary"]["DFR_B_to_E"]["k"] == 15
