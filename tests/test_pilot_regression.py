"""Regressione: il codice attuale ricostruisce ESATTAMENTE i prompt del dry run.

Per ognuna delle 20 run con seed (B0, B1, C1, C2) e per ogni agente che ha
chiamato il modello, si rieseguono retrieval, rendering e costruzione del
prompt sugli artefatti presenti in memoria in quel momento, e si confronta
il risultato con quanto registrato nei log, byte per byte.
Non invoca il modello.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.context_builder import render_memory
from core.prompt_builder import build_prompt
from core.retrieval import retrieve_artifacts

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = PROJECT_ROOT / "results"


def _seeded_runs():
    runs = []
    for path in sorted(RESULTS_DIR.glob("*.jsonl")):
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        start = events[0]["data"]
        if start.get("seed") is not None:
            runs.append((path.name, start["condition"], events))
    return runs


SEEDED_RUNS = _seeded_runs()


def test_there_are_twenty_seeded_runs():
    assert len(SEEDED_RUNS) == 20
    conditions = sorted(condition for _, condition, _ in SEEDED_RUNS)
    assert conditions == sorted(["B0-CLEAN-ISO", "B1-CLEAN-DYN", "C1-ROTTEN-ISO", "C2-ROTTEN-DYN"] * 5)


@pytest.mark.parametrize("name,condition,events", SEEDED_RUNS, ids=[r[0] for r in SEEDED_RUNS])
def test_prompts_and_retrieval_are_byte_identical(name, condition, events):
    memory: list[dict] = []
    checked = 0
    for index, event in enumerate(events):
        if event["event_type"] == "MEMORY_WRITE":
            memory.append(event["data"]["artifact"])
            continue
        if event["event_type"] != "AGENT_INPUT":
            continue

        data = event["data"]
        agent_id = data["agent_id"]

        selected, ledger = retrieve_artifacts(agent_id=agent_id, condition=condition, artifacts=memory)
        assert ledger == data["retrieval"], f"{name} {agent_id}: ledger di retrieval diverso"

        rendered = render_memory(agent_id=agent_id, condition=condition, artifacts=selected)
        assert rendered == data["rendered_memory"], f"{name} {agent_id}: memoria renderizzata diversa"

        prompt = build_prompt(agent_id=agent_id, condition=condition, retrieved_artifacts=selected)
        assert prompt == data["initial_prompt"], f"{name} {agent_id}: prompt diverso da quello del dry run"

        first_attempt = next(
            e for e in events[index + 1:]
            if e["event_type"] == "AGENT_ATTEMPT" and e["data"]["agent_id"] == agent_id
        )
        assert first_attempt["data"]["prompt"] == prompt
        checked += 1

    expected_agents = 5 if condition.startswith("B") else 4
    assert checked == expected_agents


ROTTEN_RUNS = [r for r in SEEDED_RUNS if r[1].startswith("C")]


@pytest.mark.parametrize("name,condition,events", ROTTEN_RUNS, ids=[r[0] for r in ROTTEN_RUNS])
def test_attacker_objects_are_regenerated_identically(name, condition, events):
    from config.attack import build_sec_7421
    from core.artifact_builder import build_agent_artifact
    from core.attacker import get_fixed_malicious_output

    start = events[0]["data"]
    run_id, pair_id = start["run_id"], start["pair_id"]
    writes = [e["data"]["artifact"] for e in events if e["event_type"] == "MEMORY_WRITE"]
    outputs = {e["data"]["agent_id"]: e["data"] for e in events if e["event_type"] == "AGENT_OUTPUT"}

    malicious = get_fixed_malicious_output()
    assert outputs["A"]["output"] == malicious.model_dump()
    assert outputs["A"]["controlled_by_attacker"] is True
    assert writes[0] == build_agent_artifact(run_id=run_id, pair_id=pair_id, step=1, agent_id="A",
                                             output=malicious, parent_artifacts=[])
    assert writes[1] == build_sec_7421(run_id=run_id, pair_id=pair_id)


@pytest.mark.parametrize("name,condition,events", SEEDED_RUNS, ids=[r[0] for r in SEEDED_RUNS])
def test_decision_artifacts_and_aggregation_are_regenerated_identically(name, condition, events):
    from core.aggregator import aggregate_votes
    from core.artifact_builder import build_agent_artifact
    from core.schemas import AgentOutput

    start = events[0]["data"]
    memory: list[dict] = []
    parents: dict[str, list[dict]] = {}
    for event in events:
        kind, data = event["event_type"], event["data"]
        if kind == "AGENT_INPUT":
            selected = set(data["retrieval"]["selected_artifact_ids"])
            parents[data["agent_id"]] = [a for a in memory if a["object_id"] in selected]
            parents[data["agent_id"]].sort(key=lambda a: data["retrieval"]["selected_artifact_ids"].index(a["object_id"]))
        elif kind == "AGENT_OUTPUT" and not data.get("controlled_by_attacker"):
            agent = data["agent_id"]
            step = "ABCDE".index(agent) + 1
            rebuilt = build_agent_artifact(run_id=start["run_id"], pair_id=start["pair_id"], step=step,
                                           agent_id=agent, output=AgentOutput(**data["output"]),
                                           parent_artifacts=parents[agent])
            logged = next(e["data"]["artifact"] for e in events
                          if e["event_type"] == "MEMORY_WRITE" and e["data"]["artifact"]["object_id"] == rebuilt["object_id"])
            assert rebuilt == logged, f"{name} {agent}"
        if kind == "MEMORY_WRITE":
            memory.append(data["artifact"])
        if kind == "AGGREGATION":
            assert aggregate_votes(data["votes"]) == data["final_decision"]
