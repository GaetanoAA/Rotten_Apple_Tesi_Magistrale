"""Run singola completa con modello finto: log, topologia, metadati, silenzio sui voti."""

from __future__ import annotations

import json

import pytest

import run_single
from config.model import MODEL_CONFIG


def args_for(tmp_path, condition, run_id, call_timeout="30"):
    return [
        "--phase", "pilot_smoke", "--run-dir", str(tmp_path), "--run-id", run_id,
        "--block", "0", "--seed", "24348", "--original-seed", "24348",
        "--condition", condition, "--attempt", "1",
        "--call-timeout", call_timeout, "--run-timeout", "5400",
        "--plan-sha256", "p" * 64, "--freeze-sha256", "f" * 64,
    ]


def events(tmp_path, run_id):
    lines = (tmp_path / f"{run_id}.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


@pytest.fixture(autouse=True)
def isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("ROTTEN_APPLE_RUN_DIR", str(tmp_path))
    monkeypatch.setenv("ROTTEN_APPLE_CALL_TIMEOUT_S", "30")
    monkeypatch.setitem(MODEL_CONFIG, "seed", 42)


def test_c2_run_logs_everything_and_prints_only_status(tmp_path, fake_model, fake_ollama_info, capsys):
    fake_model()
    code = run_single.main(args_for(tmp_path, "C2-ROTTEN-DYN", "t_c2"), env_info_fn=fake_ollama_info)
    assert code == 0
    printed = capsys.readouterr().out
    assert printed.strip() == "STATUS COMPLETED"

    log = events(tmp_path, "t_c2")
    start = log[0]["data"]
    assert log[0]["event_type"] == "RUN_START" and log[-1]["data"]["status"] == "COMPLETED"
    assert start["phase"] == "pilot_smoke" and start["seed"] == 24348
    assert start["model_config"]["seed"] == 24348
    assert start["pair_id"] == "pilot_smoke_b00_s24348_attack"
    assert start["model_digest"] and start["code_sha256"] and start["plan_sha256"] == "p" * 64

    by_agent = {}
    for index, event in enumerate(log):
        agent = event["data"].get("agent_id")
        if agent:
            by_agent.setdefault(agent, []).append((index, event))
    for agent in "BCDE":
        kinds = [e["event_type"] for _, e in by_agent[agent]]
        assert kinds[:2] == ["AGENT_INPUT", "AGENT_ATTEMPT"], agent
        inp = by_agent[agent][0][1]["data"]
        attempt = by_agent[agent][1][1]["data"]
        assert inp["initial_prompt"] == attempt["prompt"]
        assert attempt["raw_output"] and "latency_s" in attempt

    writes = {e["data"]["artifact"]["object_id"]: e["data"]["artifact"] for e in log if e["event_type"] == "MEMORY_WRITE"}
    selected = {e["data"]["agent_id"]: e["data"]["retrieval"]["selected_artifact_ids"]
                for e in log if e["event_type"] == "AGENT_INPUT"}
    assert [writes[i].get("claim_id") for i in selected["B"]] == ["SEC-7421"]
    assert [writes[i]["source_agent"] for i in selected["C"]] == ["B"]
    assert [writes[i]["source_agent"] for i in selected["D"]] == ["C", "B"]
    assert selected["E"] == []
    roots = {a["source_agent"]: a["root_id"] for a in writes.values() if a.get("step")}
    assert roots == {"A": None, "B": "SEC-7421", "C": "SEC-7421", "D": "SEC-7421", "E": None}


def test_b1_run_uses_honest_a(tmp_path, fake_model, fake_ollama_info):
    model = fake_model()
    assert run_single.main(args_for(tmp_path, "B1-CLEAN-DYN", "t_b1"), env_info_fn=fake_ollama_info) == 0
    assert len(model.prompts) == 5
    log = events(tmp_path, "t_b1")
    assert log[0]["data"]["pair_id"] == "pilot_smoke_b00_s24348_clean"


def test_timeout_closes_run_as_timeout(tmp_path, fake_model, fake_ollama_info, capsys):
    fake_model(lambda a, p, i: 3)
    code = run_single.main(args_for(tmp_path, "C1-ROTTEN-ISO", "t_to", call_timeout="0.3"),
                           env_info_fn=fake_ollama_info)
    assert code == 3
    assert capsys.readouterr().out.strip() == "STATUS TIMEOUT"
    log = events(tmp_path, "t_to")
    assert any(e["event_type"] == "AGENT_TIMEOUT" for e in log)
    assert log[-1]["event_type"] == "RUN_END" and log[-1]["data"]["status"] == "TIMEOUT"


def test_ollama_unreachable_writes_no_log(tmp_path, fake_model):
    from pilot.envinfo import OllamaUnavailable

    def unavailable(name):
        raise OllamaUnavailable("spento")

    fake_model()
    assert run_single.main(args_for(tmp_path, "C1-ROTTEN-ISO", "t_pre"), env_info_fn=unavailable) == 4
    assert not (tmp_path / "t_pre.jsonl").exists()


def test_agent_input_is_on_disk_before_the_model_is_called(tmp_path, fake_model, fake_ollama_info):
    from conftest import default_output

    seen = []

    def behaviour(agent_id, prompt, index):
        logged = events(tmp_path, "t_order")
        inputs = [e for e in logged if e["event_type"] == "AGENT_INPUT" and e["data"]["agent_id"] == agent_id]
        seen.append((agent_id, len(inputs) == 1 and inputs[0]["data"]["initial_prompt"] == prompt))
        return default_output(agent_id, prompt)

    fake_model(behaviour)
    assert run_single.main(args_for(tmp_path, "C2-ROTTEN-DYN", "t_order"), env_info_fn=fake_ollama_info) == 0
    assert seen == [("B", True), ("C", True), ("D", True), ("E", True)]
