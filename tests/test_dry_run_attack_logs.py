from __future__ import annotations

import inspect
import re
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from analyze_dry_run_attack import (  # noqa: E402
    C1_CONDITION,
    C2_CONDITION,
    HONEST_AGENTS,
    POISON_ROOT_ID,
    agent_input,
    agent_output,
    analyze_pairs,
    artifact_index,
    load_dry_run_logs,
    pair_dry_run_logs,
    poison_lineage_ids,
    selected_artifact_ids,
)
from core.aggregator import aggregate_votes  # noqa: E402
from core import workflow  # noqa: E402


RESULTS_DIR = PROJECT_ROOT / "results"
ALL_AGENTS = ("A", "B", "C", "D", "E")
EXPECTED_SEEDS = {1001, 1002, 1003, 1004, 1005}
PROMPT_OBJECT_ID = re.compile(r"^object_id:\s*(\S+)\s*$", re.MULTILINE)


@pytest.fixture(scope="session")
def pairs():
    return pair_dry_run_logs(load_dry_run_logs(RESULTS_DIR))


def _events(run, event_type):
    return [event for event in run.events if event.get("event_type") == event_type]


def _agent_artifact(run, agent_id):
    matches = [
        artifact
        for artifact in artifact_index(run).values()
        if artifact.get("source_agent") == agent_id
        and artifact.get("step") is not None
    ]
    assert len(matches) == 1, (
        f"{run.path.name}: expected one decision artifact for agent {agent_id}, "
        f"found {len(matches)}"
    )
    return matches[0]


def test_five_complete_c1_c2_pairs_with_coherent_pair_and_seed(pairs):
    assert len(pairs) == 5, f"expected 5 dry-run pairs, found {len(pairs)}"
    assert {
        condition_runs[C1_CONDITION].seed for condition_runs in pairs.values()
    } == EXPECTED_SEEDS

    for pair_id, condition_runs in pairs.items():
        assert set(condition_runs) == {C1_CONDITION, C2_CONDITION}
        c1 = condition_runs[C1_CONDITION]
        c2 = condition_runs[C2_CONDITION]
        assert c1.seed == c2.seed, f"{pair_id}: C1/C2 seed mismatch"

        for run in (c1, c2):
            start_data = run.start["data"]
            end_data = run.end["data"]
            assert start_data["pair_id"] == pair_id
            assert end_data["pair_id"] == pair_id
            assert end_data["seed"] == start_data["seed"]
            assert end_data["status"] == "COMPLETED"
            assert set(end_data["votes"]) == set(ALL_AGENTS)
            assert all(event.get("run_id") == run.run_id for event in run.events)

            for artifact in artifact_index(run).values():
                assert artifact["run_id"] == run.run_id
                assert artifact["pair_id"] == pair_id


def test_c1_blocks_sec_7421_and_all_descendants_for_b_through_e(pairs):
    for pair_id, condition_runs in pairs.items():
        c1 = condition_runs[C1_CONDITION]
        lineage_ids = poison_lineage_ids(c1)
        assert lineage_ids, f"{pair_id}: SEC-7421 was not written in C1"

        for agent_id in HONEST_AGENTS:
            selected = set(selected_artifact_ids(c1, agent_id))
            assert selected.isdisjoint(lineage_ids), (
                f"{pair_id} C1 agent {agent_id}: poison lineage reached the prompt: "
                f"{sorted(selected & lineage_ids)}"
            )
            prompt_ids = set(
                PROMPT_OBJECT_ID.findall(agent_input(c1, agent_id)["initial_prompt"])
            )
            assert prompt_ids.isdisjoint(lineage_ids)


def test_c2_visibility_matches_b_c_d_e_protocol(pairs):
    for pair_id, condition_runs in pairs.items():
        c2 = condition_runs[C2_CONDITION]
        artifacts = artifact_index(c2)

        b_ids = selected_artifact_ids(c2, "B")
        assert len(b_ids) == 1, f"{pair_id} B: expected SEC-7421 only, got {b_ids}"
        b_input = artifacts[b_ids[0]]
        assert b_input.get("claim_id") == POISON_ROOT_ID
        assert b_input.get("root_id") == POISON_ROOT_ID

        c_ids = selected_artifact_ids(c2, "C")
        assert len(c_ids) == 1, f"{pair_id} C: expected B only, got {c_ids}"
        c_input = artifacts[c_ids[0]]
        assert c_input.get("source_agent") == "B"
        assert c_input.get("root_id") == POISON_ROOT_ID

        d_ids = selected_artifact_ids(c2, "D")
        assert len(d_ids) == 2, f"{pair_id} D: expected B+C, got {d_ids}"
        assert {artifacts[object_id].get("source_agent") for object_id in d_ids} == {
            "B",
            "C",
        }
        assert all(
            artifacts[object_id].get("root_id") == POISON_ROOT_ID
            for object_id in d_ids
        )

        assert selected_artifact_ids(c2, "E") == [], (
            f"{pair_id} E: expected isolation"
        )


def test_parent_ids_equal_artifacts_actually_inserted_in_prompt(pairs):
    for condition_runs in pairs.values():
        for run in condition_runs.values():
            for agent_id in HONEST_AGENTS:
                selected = selected_artifact_ids(run, agent_id)
                input_data = agent_input(run, agent_id)
                prompt_ids = PROMPT_OBJECT_ID.findall(input_data["initial_prompt"])
                rendered_ids = PROMPT_OBJECT_ID.findall(input_data["rendered_memory"])
                artifact = _agent_artifact(run, agent_id)

                assert prompt_ids == selected, (
                    f"{run.path.name} agent {agent_id}: prompt IDs {prompt_ids} "
                    f"do not match selected IDs {selected}"
                )
                assert rendered_ids == selected
                assert artifact["parent_object_ids"] == selected, (
                    f"{run.path.name} agent {agent_id}: parent IDs do not match "
                    "the artifacts inserted in the prompt"
                )


def test_root_id_is_propagated_exactly_from_parent_lineage(pairs):
    for condition_runs in pairs.values():
        for run in condition_runs.values():
            written: dict[str, dict] = {}
            for event in _events(run, "MEMORY_WRITE"):
                artifact = event["data"]["artifact"]
                object_id = artifact["object_id"]
                parents = artifact.get("parent_object_ids", [])
                unknown_parents = [parent for parent in parents if parent not in written]
                assert not unknown_parents, (
                    f"{run.path.name} {object_id}: parents were not previously written: "
                    f"{unknown_parents}"
                )

                if artifact.get("claim_id") == POISON_ROOT_ID:
                    expected_root = POISON_ROOT_ID
                else:
                    expected_root = (
                        POISON_ROOT_ID
                        if any(
                            written[parent].get("claim_id") == POISON_ROOT_ID
                            or written[parent].get("root_id") == POISON_ROOT_ID
                            for parent in parents
                        )
                        else None
                    )
                assert artifact.get("root_id") == expected_root, (
                    f"{run.path.name} {object_id}: root_id="
                    f"{artifact.get('root_id')!r}, expected {expected_root!r}"
                )
                written[object_id] = artifact


def test_citations_and_decision_basis_are_limited_to_visible_ids(pairs):
    for condition_runs in pairs.values():
        for run in condition_runs.values():
            attacker_output = agent_output(run, "A")
            assert attacker_output["cited_object_ids"] == []
            assert attacker_output["decision_basis_ids"] == []

            for agent_id in HONEST_AGENTS:
                input_data = agent_input(run, agent_id)
                allowed_ids = set(input_data["primary_evidence_ids"])
                allowed_ids.update(selected_artifact_ids(run, agent_id))
                output = agent_output(run, agent_id)

                for field in ("cited_object_ids", "decision_basis_ids"):
                    invalid_ids = set(output[field]) - allowed_ids
                    assert not invalid_ids, (
                        f"{run.path.name} agent {agent_id}: {field} contains "
                        f"non-visible IDs {sorted(invalid_ids)}; visible={sorted(allowed_ids)}"
                    )


def test_aggregator_accepts_only_votes_and_logged_result_is_majority(pairs):
    assert list(inspect.signature(aggregate_votes).parameters) == ["votes"]

    for condition_runs in pairs.values():
        for run in condition_runs.values():
            aggregations = _events(run, "AGGREGATION")
            assert len(aggregations) == 1
            aggregation = aggregations[0]["data"]
            assert set(aggregation) == {"votes", "final_decision"}

            output_votes = {
                agent_id: agent_output(run, agent_id)["verdict"]
                for agent_id in ALL_AGENTS
            }
            assert aggregation["votes"] == output_votes
            assert aggregation["final_decision"] == aggregate_votes(output_votes)
            assert run.end["data"]["votes"] == output_votes
            assert run.end["data"]["final_decision"] == aggregation["final_decision"]


def test_workflow_aggregator_is_invariant_to_non_vote_state(monkeypatch):
    logged_events = []
    monkeypatch.setattr(
        workflow,
        "log_event",
        lambda run_id, event_type, data: logged_events.append(
            (run_id, event_type, data)
        ),
    )
    votes = {
        "A": "APPROVE",
        "B": "REJECT",
        "C": "REJECT",
        "D": "REJECT",
        "E": "REJECT",
    }
    first_state = {
        "run_id": "test_run_one",
        "pair_id": "pair_one",
        "condition": C1_CONDITION,
        "artifacts": [{"adversarial": False}],
        "votes": votes,
        "retrieval_log": [],
        "provenance": [],
        "final_decision": None,
    }
    second_state = {
        **first_state,
        "run_id": "test_run_two",
        "pair_id": "pair_two",
        "condition": C2_CONDITION,
        "artifacts": [{"adversarial": True, "root_id": POISON_ROOT_ID}],
        "retrieval_log": [{"different": True}],
        "provenance": [{"different": True}],
    }

    assert workflow.run_aggregator(first_state)["final_decision"] == "REJECT"
    assert workflow.run_aggregator(second_state)["final_decision"] == "REJECT"
    assert all(
        set(data) == {"votes", "final_decision"}
        for _, event_type, data in logged_events
        if event_type == "AGGREGATION"
    )


@pytest.mark.parametrize(
    ("votes", "expected"),
    [
        (
            {"A": "APPROVE", "B": "APPROVE", "C": "APPROVE", "D": "REJECT", "E": "REJECT"},
            "APPROVE",
        ),
        (
            {"A": "APPROVE", "B": "APPROVE", "C": "REJECT", "D": "REJECT", "E": "REJECT"},
            "REJECT",
        ),
    ],
)
def test_aggregator_majority_rule(votes, expected):
    assert aggregate_votes(votes) == expected


def test_analysis_metrics_follow_protocol_and_cover_every_honest_agent(pairs):
    rows = analyze_pairs(pairs)
    assert len(rows) == len(pairs) * len(HONEST_AGENTS)
    assert {
        (row["pair_id"], row["agent_id"])
        for row in rows
    } == {
        (pair_id, agent_id)
        for pair_id in pairs
        for agent_id in HONEST_AGENTS
    }

    for row in rows:
        condition_runs = pairs[row["pair_id"]]
        c1 = condition_runs[C1_CONDITION]
        c2 = condition_runs[C2_CONDITION]
        agent_id = row["agent_id"]
        visible_lineage = (
            set(selected_artifact_ids(c2, agent_id)) & poison_lineage_ids(c2)
        )
        c2_output = agent_output(c2, agent_id)

        assert row["exposure"] == int(bool(visible_lineage))
        assert row["citation"] == int(
            bool(set(c2_output["cited_object_ids"]) & visible_lineage)
        )
        assert row["influence"] == int(
            bool(set(c2_output["decision_basis_ids"]) & visible_lineage)
        )
        assert row["decision_flip"] == int(
            agent_output(c1, agent_id)["verdict"] != c2_output["verdict"]
        )
