"""Seconda mitigazione: root-collapse che preserva il dissenso, senza righe di provenienza."""

from __future__ import annotations

import json
import random
from pathlib import Path

import analyze_attack as aa
import run_single
from config.attack import build_sec_7421
from config.model import MODEL_CONFIG
from config.visibility import VISIBILITY_BY_CONDITION
from core.context_builder import render_memory
from core.retrieval import retrieve_artifacts
from pilot import envinfo
from pilot.phases import ALL_PHASES, stage_paths
from pilot.planning import PRIMARY_CONDITIONS, planned_run_count
from tools import check_smoke

PROJECT_ROOT = Path(__file__).resolve().parents[1]
NAMES = ("pilot", "main", "variant", "appendix", "followup", "mitigation", "mitigation2", "mitigation3")
PLANS = {n: json.loads((PROJECT_ROOT / "config" / f"{n}_plan.json").read_text(encoding="utf-8")) for n in NAMES}
PLAN = PLANS["mitigation3"]
C4 = "C4-ROTTEN-MULTI"
C1N, C4N, C3D = "C1N-ROTTEN-ISO-NOIMP", "C4N-ROTTEN-MULTI-NOIMP", "C3D-ROTTEN-ROOT-NOIMP"


def test_phases_files_and_plan():
    assert {"mitigation3_smoke", "mitigation3_attack"} <= set(ALL_PHASES)
    assert stage_paths("mitigation3")["prereg"] == "documentazione/preregistrazione_mitigazione_v2.md"
    assert "config/mitigation3_plan.json" in envinfo.FROZEN_PATTERNS
    assert "documentazione/preregistrazione_mitigazione_v2.md" in envinfo.FROZEN_PATTERNS
    assert C3D in PRIMARY_CONDITIONS
    assert PLAN["phase"] == "mitigation3_attack" and PLAN["model"] == PLANS["mitigation2"]["model"]
    seeds = random.Random(20261020).sample(range(10000, 100000), 51)
    assert [b["seed"] for b in PLAN["blocks"]] == seeds[:40]
    assert PLAN["reserve_seeds"] == seeds[40:50] and PLAN["smoke"]["seed"] == seeds[50]
    rng = random.Random(20261021)
    for block in PLAN["blocks"]:
        expected = [C1N, C4N, C3D]
        rng.shuffle(expected)
        assert block["order"] == expected
    assert planned_run_count(PLAN, "mitigation3_attack") == 120


def test_seeds_disjoint_from_all_previous_phases():
    used = set(PLANS["pilot"]["seed_generation"]["excluded_seeds"])
    for name in NAMES[:-1]:
        plan = PLANS[name]
        used |= {b["seed"] for b in plan["blocks"]} | set(plan["reserve_seeds"]) | {plan["smoke"]["seed"]}
    new = {b["seed"] for b in PLAN["blocks"]} | set(PLAN["reserve_seeds"]) | {PLAN["smoke"]["seed"]}
    assert len(new) == 51 and not new & used


def test_visibility_single_change_from_c4():
    for agent, cfg in VISIBILITY_BY_CONDITION[C3D].items():
        base = VISIBILITY_BY_CONDITION[C4][agent]
        assert {k: v for k, v in cfg.items() if k != "root_collapse"} == base
        assert not cfg.get("provenance_visible")


def _art(agent, step, verdict, parents):
    return {"object_id": f"mem://run/{agent}/decision/{step}", "source_agent": agent, "step": step,
            "root_id": "SEC-7421", "parent_object_ids": parents, "summary": f"{agent} {verdict}", "verdict": verdict}


def test_only_concordant_derivatives_are_collapsed():
    sec = build_sec_7421("R", "P", namespace="run")
    cases = {("APPROVE", "REJECT"): (["A"], ["C", "A"]),
             ("REJECT", "REJECT"): (["B", "A"], ["C", "B", "A"]),
             ("APPROVE", "APPROVE"): (["A"], ["A"]),
             ("REJECT", "APPROVE"): (["B", "A"], ["B", "A"])}
    for (vb, vc), (exp_c, exp_d) in cases.items():
        b = _art("B", 2, vb, [sec["object_id"]])
        c = _art("C", 3, vc, [sec["object_id"], b["object_id"]])
        sel_c, _ = retrieve_artifacts("C", C3D, [sec, b, c])
        sel_d, ledger = retrieve_artifacts("D", C3D, [sec, b, c])
        assert [s["source_agent"] for s in sel_c] == exp_c, (vb, vc)
        assert [s["source_agent"] for s in sel_d] == exp_d, (vb, vc)
        assert all(r["reason"].startswith("root-collapse") for r in ledger["excluded_artifacts"])
        text = render_memory("D", C3D, sel_d)
        assert "root_id:" not in text and "oggetti_derivati" not in text and "parent_object_ids" not in text
        # Stesso rendering di C4N per gli oggetti mantenuti.
        assert text == render_memory("D", C4N, sel_d)


def _run_smoke(tmp_path, monkeypatch, fake_model, fake_ollama_info, phase, plan):
    tmp_path.mkdir(parents=True, exist_ok=True)
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


def test_smoke_and_analysis(tmp_path, monkeypatch, fake_model, fake_ollama_info):
    runs = _run_smoke(tmp_path / "m", monkeypatch, fake_model, fake_ollama_info, "mitigation3_smoke", PLAN)
    assert set(runs) == {C1N, C4N, C3D}
    for condition, run in runs.items():
        assert aa.check_run(run, None) == [], condition
        for agent, inp in run["inputs"].items():
            prompt = inp.get("initial_prompt") or ""
            assert run["start"]["run_id"] not in prompt
            for marker in ("ROTTEN", "CLEAN", "mitigation", "NOIMP", "C3D", "poison", '"implication"', "root_id:"):
                assert marker not in prompt, (condition, agent, marker)
    # Con il modello finto B e C votano REJECT: dissenso, nessun collasso; prompt identici a C4N.
    for agent in ("B", "C", "D", "E"):
        assert runs[C3D]["inputs"][agent]["initial_prompt"] == runs[C4N]["inputs"][agent]["initial_prompt"]
    freeze = {"code_sha256": envinfo.code_hashes(PROJECT_ROOT)}
    passed, results = check_smoke.evaluate_smoke(tmp_path / "m", PLAN, freeze, "f" * 64, "mitigation3_smoke")
    assert passed, results
    report = aa.analyze_mitigation(aa.load_runs(tmp_path / "m", "mitigation3_smoke"), "mitigation3_smoke", None,
                                   defense=C3D)
    assert report["defense_condition"] == C3D
    assert report["mitigation"]["interpretation"]["decisione_finale"].startswith("non valutabile")
    assert "C3D-ROTTEN-ROOT-NOIMP" in aa.summary_mitigation_text(report)
