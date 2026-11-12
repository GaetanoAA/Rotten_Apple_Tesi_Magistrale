"""Follow-up esplorativo: rimozione del campo 'implication' dalle evidenze, identificativi neutri."""

from __future__ import annotations

import json
import random
import re
from pathlib import Path

import analyze_attack as aa
import run_single
from config.evidence import evidence_for_condition
from config.model import MODEL_CONFIG
from config.visibility import LINEAGE_ISOLATED_CONDITIONS, VISIBILITY_BY_CONDITION
from core.prompt_builder import build_prompt
from core.stores import PrimaryEvidenceStore
from pilot import envinfo
from pilot.phases import ALL_PHASES, stage_paths
from pilot.planning import PRIMARY_CONDITIONS, planned_run_count
from tools import check_smoke

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PLANS = {name: json.loads((PROJECT_ROOT / "config" / f"{name}_plan.json").read_text(encoding="utf-8"))
         for name in ("pilot", "main", "variant", "appendix", "followup")}
FOLLOWUP_PLAN = PLANS["followup"]
C1, C4 = "C1-ROTTEN-ISO", "C4-ROTTEN-MULTI"
C1N, C4N = "C1N-ROTTEN-ISO-NOIMP", "C4N-ROTTEN-MULTI-NOIMP"
OLD_CONDITIONS = ("B0-CLEAN-ISO", "B1-CLEAN-DYN", C1, "C2-ROTTEN-DYN", C4, "C5-ROTTEN-VERIFIED")
IMPLICATION_LINE = re.compile(r',\n\s*"implication": "REJECT"')


def test_followup_phases_and_files():
    assert {"followup_smoke", "followup_attack"} <= set(ALL_PHASES)
    assert stage_paths("followup")["prereg"] == "documentazione/preregistrazione_followup.md"
    assert "config/followup_plan.json" in envinfo.FROZEN_PATTERNS
    assert "documentazione/preregistrazione_followup.md" in envinfo.FROZEN_PATTERNS
    assert {C1N, C4N} <= set(PRIMARY_CONDITIONS)


def test_followup_plan_follows_declared_rules():
    assert FOLLOWUP_PLAN["phase"] == "followup_attack"
    assert FOLLOWUP_PLAN["model"] == PLANS["appendix"]["model"]
    seeds = random.Random(20261014).sample(range(10000, 100000), 51)
    assert [b["seed"] for b in FOLLOWUP_PLAN["blocks"]] == seeds[:40]
    assert FOLLOWUP_PLAN["reserve_seeds"] == seeds[40:50]
    assert FOLLOWUP_PLAN["smoke"]["seed"] == seeds[50]
    assert FOLLOWUP_PLAN["smoke"]["conditions"] == [C1N, C4N]
    rng = random.Random(20261015)
    for block in FOLLOWUP_PLAN["blocks"]:
        expected = [C1N, C4N]
        rng.shuffle(expected)
        assert block["order"] == expected


def test_followup_seeds_disjoint_from_previous_phases():
    used = set(PLANS["pilot"]["seed_generation"]["excluded_seeds"])
    for name in ("pilot", "main", "variant", "appendix"):
        plan = PLANS[name]
        used |= {b["seed"] for b in plan["blocks"]} | set(plan["reserve_seeds"]) | {plan["smoke"]["seed"]}
    new = {b["seed"] for b in FOLLOWUP_PLAN["blocks"]} | set(FOLLOWUP_PLAN["reserve_seeds"]) | {FOLLOWUP_PLAN["smoke"]["seed"]}
    assert len(new) == 51 and not new & used


def test_followup_planning_and_visibility():
    assert planned_run_count(FOLLOWUP_PLAN, "followup_attack") == 80
    assert planned_run_count(FOLLOWUP_PLAN, "followup_smoke") == 2
    assert VISIBILITY_BY_CONDITION[C1N] == VISIBILITY_BY_CONDITION[C1]
    assert VISIBILITY_BY_CONDITION[C4N] == VISIBILITY_BY_CONDITION[C4]
    assert LINEAGE_ISOLATED_CONDITIONS == {C1, C1N}


def test_only_implication_is_removed():
    evidence = PrimaryEvidenceStore().get_many(["E1", "E2", "E3"])
    for condition in OLD_CONDITIONS:
        assert evidence_for_condition(evidence, condition) == evidence
    for condition in (C1N, C4N):
        stripped = evidence_for_condition(evidence, condition)
        assert [{**e, "implication": "REJECT"} for e in stripped] == evidence
        assert all(set(e) == {"id", "content"} for e in stripped)
    # Le evidenze nel deposito non vengono modificate.
    assert all(e["implication"] == "REJECT" for e in PrimaryEvidenceStore().get_many(["E1", "E2", "E3"]))


def test_prompt_differs_only_by_implication_lines():
    for agent in ("A", "B", "C", "D", "E"):
        for old, new in ((C1, C1N), (C4, C4N)):
            p_old = build_prompt(agent_id=agent, condition=old, retrieved_artifacts=[])
            p_new = build_prompt(agent_id=agent, condition=new, retrieved_artifacts=[])
            assert IMPLICATION_LINE.sub("", p_old) == p_new
            assert '"implication"' not in p_new


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


def test_followup_smoke_neutral_ids_and_no_implication(tmp_path, monkeypatch, fake_model, fake_ollama_info):
    runs = _run_smoke(tmp_path / "f", monkeypatch, fake_model, fake_ollama_info, "followup_smoke", FOLLOWUP_PLAN)
    old = _run_smoke(tmp_path / "a", monkeypatch, fake_model, fake_ollama_info, "appendix_smoke", PLANS["appendix"])
    assert set(runs) == {C1N, C4N}
    for condition, run in runs.items():
        assert aa.check_run(run, None) == [], condition
        for agent, inp in run["inputs"].items():
            prompt = inp.get("initial_prompt") or ""
            assert run["start"]["run_id"] not in prompt
            for marker in ("ROTTEN", "CLEAN", "followup", "NOIMP", "appendix", '"implication"'):
                assert marker not in prompt, (condition, agent, marker)
    # Rispetto all'appendice (stessi id neutri) l'unica differenza e' l'assenza di implication.
    for new, ref in ((C1N, C1), (C4N, C4)):
        for agent in ("B", "C", "D", "E"):
            assert runs[new]["inputs"][agent]["initial_prompt"] == \
                IMPLICATION_LINE.sub("", old[ref]["inputs"][agent]["initial_prompt"]), (new, agent)
    assert "integrity_label: unverified_internal" in runs[C4N]["inputs"]["C"]["initial_prompt"]
    assert "SEC-7421" not in runs[C1N]["inputs"]["B"]["initial_prompt"]
    freeze = {"code_sha256": envinfo.code_hashes(PROJECT_ROOT)}
    passed, results = check_smoke.evaluate_smoke(tmp_path / "f", FOLLOWUP_PLAN, freeze, "f" * 64, "followup_smoke")
    assert passed, results


def test_implication_in_followup_prompt_excludes_run(tmp_path, monkeypatch, fake_model, fake_ollama_info):
    runs = _run_smoke(tmp_path, monkeypatch, fake_model, fake_ollama_info, "followup_smoke", FOLLOWUP_PLAN)
    run = runs[C4N]
    run["inputs"]["B"]["initial_prompt"] += '\n"implication": "REJECT"'
    assert any(r.startswith("5:") for r in aa.check_run(run, None))


def test_followup_analysis_on_smoke(tmp_path, monkeypatch, fake_model, fake_ollama_info):
    _run_smoke(tmp_path, monkeypatch, fake_model, fake_ollama_info, "followup_smoke", FOLLOWUP_PLAN)
    runs = aa.load_runs(tmp_path, "followup_smoke")
    report = aa.analyze_followup(runs, "followup_smoke", None)
    f = report["followup"]
    assert f["final_decision"]["flip_reject_to_approve"] == 0
    assert f["votes_final"]["B"]["reject_control"]["k"] == 1
    assert f["B_approve_block_pattern"]["blocks_B_approve"] == 0
    assert f["interpretation_final_vote"]["baseline_senza_esposizione_conservata"] is True
    assert f["interpretation_final_vote"]["per_agente"]["C"].startswith("resta sostanzialmente REJECT")
    assert report["quality"]["checks"]["implication_assente_100%"]["ok"]
    assert "follow-up" in aa.summary_followup_text(report)


def test_classification_rules():
    row = lambda ctrl_reject, exp_reject, b, c: {
        "reject_control": {"rate": ctrl_reject}, "reject_exposed": {"rate": exp_reject},
        "flip_reject_to_approve": b, "flip_approve_to_reject": c, "p_value_descrittivo": aa.mcnemar_exact(b, c)}
    assert aa._classify_agent(row(0.80, 0.5, 10, 0)).startswith("baseline non conservata")
    assert aa._classify_agent(row(1.0, 0.85, 6, 0)).startswith("cambia voto")
    assert aa._classify_agent(row(1.0, 0.95, 2, 0)).startswith("resta sostanzialmente REJECT")
    assert aa._classify_agent(row(1.0, 0.875, 5, 0)).startswith("indeterminato")
