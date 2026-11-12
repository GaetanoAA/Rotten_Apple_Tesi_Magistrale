"""Executor: retry invariato, raw_output registrato, timeout senza retry."""

from __future__ import annotations

import json

import pytest

import core.agent_executor as executor
from config.attack import build_sec_7421
from core.prompt_builder import build_prompt
from core.schemas import AgentOutput

SEC = build_sec_7421("run_test", "pair_test")


def legacy_retry_prompt(base_prompt, allowed_ids):
    # Testo copiato dal codice del dry run: non deve cambiare.
    return (
        base_prompt
        + "\n\n"
        + "RETRY VALIDATION NOTICE\n"
        + "La risposta precedente non rispettava i vincoli. "
        + "Nei campi cited_object_ids e decision_basis_ids "
        + "puoi utilizzare esclusivamente identificativi "
        + "realmente presenti nel contesto.\n"
        + f"Identificativi consentiti: {sorted(allowed_ids)}\n"
        + "Genera nuovamente l'output rispettando rigorosamente "
        + "questi vincoli."
    )


def output(cited):
    return AgentOutput(verdict="REJECT", rationale_public="r", summary="s",
                       cited_object_ids=cited, decision_basis_ids=["E1"], confidence_claimed=1.0)


def test_invalid_ids_trigger_the_unchanged_retry_prompt(fake_model, monkeypatch):
    monkeypatch.delenv(executor.CALL_TIMEOUT_ENV, raising=False)
    model = fake_model(lambda a, p, i: output(["INVENTATO"]) if i == 0 else output(["E1"]))
    result, attempts = executor.execute_agent("B", "C2-ROTTEN-DYN", [SEC])
    base = build_prompt(agent_id="B", condition="C2-ROTTEN-DYN", retrieved_artifacts=[SEC])
    assert model.prompts == [base, legacy_retry_prompt(base, {"E1", "E2", SEC["object_id"]})]
    assert [a["valid"] for a in attempts] == [False, True]
    assert attempts[0]["invalid_cited_object_ids"] == ["INVENTATO"]
    assert result.cited_object_ids == ["E1"]


def test_raw_output_latency_and_json_safe_generation_info(fake_model, monkeypatch):
    monkeypatch.delenv(executor.CALL_TIMEOUT_ENV, raising=False)
    fake_model()
    _, attempts = executor.execute_agent("E", "C2-ROTTEN-DYN", [])
    attempt = attempts[0]
    assert json.loads(attempt["raw_output"])["verdict"] == "REJECT"
    assert attempt["generation_info"]["done_reason"] == "stop"
    assert attempt["generation_info"]["extra"] == "oggetto-non-serializzabile"
    json.dumps(attempt)  # tutto serializzabile nel log
    assert attempt["latency_s"] >= 0


def test_parse_error_follows_legacy_retry_path(fake_model, monkeypatch):
    monkeypatch.delenv(executor.CALL_TIMEOUT_ENV, raising=False)
    fake_model(lambda a, p, i: ValueError("json non valido") if i == 0 else output(["E1"]))
    _, attempts = executor.execute_agent("E", "C1-ROTTEN-ISO", [])
    assert attempts[0]["error_type"] == "ValueError"
    assert attempts[0]["raw_output"] == "json non valido"
    assert attempts[1]["valid"] is True


def test_without_timeout_the_call_runs_in_the_main_thread(fake_model, monkeypatch):
    monkeypatch.delenv(executor.CALL_TIMEOUT_ENV, raising=False)
    model = fake_model()
    executor.execute_agent("E", "C1-ROTTEN-ISO", [])
    assert model.threads == [True]


def test_call_timeout_aborts_without_retry(fake_model, monkeypatch):
    monkeypatch.setenv(executor.CALL_TIMEOUT_ENV, "0.3")
    model = fake_model(lambda a, p, i: 3)  # la chiamata dura 3 s
    with pytest.raises(executor.AgentCallTimeout) as info:
        executor.execute_agent("E", "C1-ROTTEN-ISO", [])
    assert len(model.prompts) == 1
    assert [a["error_type"] for a in info.value.attempts] == ["AgentCallTimeout"]


def test_with_timeout_a_fast_call_succeeds(fake_model, monkeypatch):
    monkeypatch.setenv(executor.CALL_TIMEOUT_ENV, "30")
    model = fake_model()
    result, attempts = executor.execute_agent("E", "C1-ROTTEN-ISO", [])
    assert result.verdict == "REJECT" and len(attempts) == 1
    assert model.threads == [False]
