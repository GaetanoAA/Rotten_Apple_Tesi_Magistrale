"""Regole di ripresa, rilancio e sostituzione (preregistrazione §4)."""

from __future__ import annotations

import json
import random
from pathlib import Path

from pilot.planning import Record, next_action, planned_run_count, records_from_sources

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REAL_PLAN = json.loads((PROJECT_ROOT / "config" / "pilot_plan.json").read_text(encoding="utf-8"))

B0, B1, C1, C2 = "B0-CLEAN-ISO", "B1-CLEAN-DYN", "C1-ROTTEN-ISO", "C2-ROTTEN-DYN"

PLAN = {
    "max_technical_reruns_per_run": 2,
    "smoke": {"seed": 7, "conditions": [C1, C2]},
    "blocks": [
        {"block": 1, "seed": 11, "order": [B0, C1, C2]},
        {"block": 2, "seed": 22, "order": [C2, C1]},
    ],
    "reserve_seeds": [91, 92],
}


def rec(block, seed, condition, status, attempt=1):
    return Record(f"r{block}{seed}{condition}{attempt}", block, seed, condition, attempt, status)


def test_starts_from_first_block_in_planned_order():
    action = next_action(PLAN, "pilot_attack", []).action
    assert (action.block, action.seed, action.condition, action.attempt) == (1, 11, B0, 1)


def test_completed_runs_are_skipped():
    records = [rec(1, 11, B0, "COMPLETED")]
    assert next_action(PLAN, "pilot_attack", records).action.condition == C1


def test_failures_are_retried_up_to_three_attempts():
    records = [rec(1, 11, B0, "COMPLETED"), rec(1, 11, C1, "FAILED", 1), rec(1, 11, C1, "TIMEOUT", 2)]
    action = next_action(PLAN, "pilot_attack", records).action
    assert (action.condition, action.attempt, action.seed) == (C1, 3, 11)


def test_primary_condition_exhausted_replaces_whole_block_with_reserve():
    records = [rec(1, 11, B0, "COMPLETED")] + [rec(1, 11, C1, "FAILED", i) for i in (1, 2, 3)]
    decision = next_action(PLAN, "pilot_attack", records)
    assert decision.substitutions == [(1, 11, 91)]
    action = decision.action
    assert (action.block, action.seed, action.original_seed, action.condition) == (1, 91, 11, B0)


def test_clean_condition_exhausted_is_excluded_without_replacement():
    records = [rec(1, 11, B0, "INCOMPLETE", i) for i in (1, 2, 3)]
    decision = next_action(PLAN, "pilot_attack", records)
    assert decision.excluded == [(1, 11, B0)]
    assert decision.substitutions == []
    assert (decision.action.seed, decision.action.condition) == (11, C1)


def test_interruptions_and_precheck_failures_do_not_consume_attempts():
    records = [rec(1, 11, B0, "INTERRUPTED", i) for i in (1, 2, 3, 4)]
    records += [rec(1, 11, B0, "PRECHECK_FAILED", 5)]
    action = next_action(PLAN, "pilot_attack", records).action
    assert (action.condition, action.attempt) == (B0, 6)


def test_done_and_reserves_exhausted():
    done = [rec(1, 11, c, "COMPLETED") for c in (B0, C1, C2)] + [rec(2, 22, c, "COMPLETED") for c in (C1, C2)]
    assert next_action(PLAN, "pilot_attack", done).done

    records = [rec(1, 11, B0, "COMPLETED")]
    records += [rec(1, s, C1, "FAILED", i) for s in (11, 91, 92) for i in (1, 2, 3)]
    records += [rec(1, s, B0, "COMPLETED") for s in (91, 92)]
    decision = next_action(PLAN, "pilot_attack", records)
    assert decision.stop_reason and not decision.done


def test_smoke_phase_uses_only_the_smoke_seed_and_no_reserves():
    action = next_action(PLAN, "pilot_smoke", []).action
    assert (action.block, action.seed) == (0, 7)


def test_status_precedence_log_then_ledger_then_incomplete():
    launches = [{"run_id": i, "block": 1, "seed": 11, "condition": B0, "attempt": n}
                for n, i in enumerate(("a", "b", "c"), start=1)]
    records = records_from_sources(launches, {"a": "TIMEOUT", "b": "INTERRUPTED"}, {"a": "COMPLETED"})
    assert [r.status for r in records] == ["COMPLETED", "INTERRUPTED", "INCOMPLETE"]


def test_real_plan_matches_preregistration():
    assert planned_run_count(REAL_PLAN, "pilot_attack") == 60
    assert planned_run_count(REAL_PLAN, "pilot_smoke") == 4
    seeds = [b["seed"] for b in REAL_PLAN["blocks"]]
    assert len(set(seeds)) == 20
    used = set(seeds) | set(REAL_PLAN["reserve_seeds"]) | {REAL_PLAN["smoke"]["seed"]}
    assert len(used) == 31
    assert not used & {42, 1001, 1002, 1003, 1004, 1005}
    for i, block in enumerate(REAL_PLAN["blocks"]):
        expected = {B0, B1, C1, C2} if i < 10 else {C1, C2}
        assert set(block["order"]) == expected and len(block["order"]) == len(expected)


def test_real_plan_is_reproducible_from_declared_rule():
    sample = random.Random(20261002).sample(range(10000, 100000), 31)
    order_rng = random.Random(20261003)
    for i, block in enumerate(REAL_PLAN["blocks"]):
        conditions = [B0, B1, C1, C2] if i < 10 else [C1, C2]
        order_rng.shuffle(conditions)
        assert block["seed"] == sample[i]
        assert block["order"] == conditions
    assert REAL_PLAN["reserve_seeds"] == sample[20:30]
    assert REAL_PLAN["smoke"]["seed"] == sample[30]
