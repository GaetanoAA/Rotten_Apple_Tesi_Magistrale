"""La richiesta inviata a Ollama e' identica a quella del dry run.

Usa la vera libreria langchain-ollama e sostituisce solo l'ultimo passo,
ollama.Client.chat, con una funzione che registra i parametri ricevuti e
restituisce una risposta finta: nessuna chiamata di rete, nessun modello.

Confronta:
  - percorso del dry run: get_model().with_structured_output(AgentOutput).invoke(prompt)
  - percorso nuovo: execute_agent(...) con callback raw_output, con e senza timeout.
"""

from __future__ import annotations

import json

import ollama
import pytest

import core.agent_executor as executor
from config.attack import build_sec_7421
from core.model_client import get_model
from core.prompt_builder import build_prompt
from core.schemas import AgentOutput

SEC = build_sec_7421("run_test", "pair_test")
VALID = AgentOutput(
    verdict="REJECT",
    rationale_public="La firma non e' valida.",
    summary="Pacchetto non attendibile.",
    cited_object_ids=["E1", "E2"],
    decision_basis_ids=["E1", "E2"],
    confidence_claimed=1.0,
)
CONTENT = json.dumps(VALID.model_dump())


@pytest.fixture
def captured(monkeypatch):
    calls: list[dict] = []

    def fake_chat(self, **kwargs):
        calls.append(kwargs)
        chunk = {
            "model": kwargs.get("model"),
            "created_at": "2026-10-02T00:00:00Z",
            "message": {"role": "assistant", "content": CONTENT},
            "done": True,
            "done_reason": "stop",
            "total_duration": 1,
            "load_duration": 1,
            "prompt_eval_count": 10,
            "prompt_eval_duration": 1,
            "eval_count": 20,
            "eval_duration": 1,
        }
        return iter([chunk]) if kwargs.get("stream") else chunk

    monkeypatch.setattr(ollama.Client, "chat", fake_chat)
    return calls


def legacy_request(captured, prompt):
    result = get_model().with_structured_output(AgentOutput).invoke(prompt)
    assert result == VALID
    return captured[-1]


@pytest.mark.parametrize("timeout", [None, "30"])
def test_request_is_identical_to_dry_run(captured, monkeypatch, timeout):
    if timeout is None:
        monkeypatch.delenv(executor.CALL_TIMEOUT_ENV, raising=False)
    else:
        monkeypatch.setenv(executor.CALL_TIMEOUT_ENV, timeout)

    prompt = build_prompt(agent_id="B", condition="C2-ROTTEN-DYN", retrieved_artifacts=[SEC])
    legacy = legacy_request(captured, prompt)

    result, attempts = executor.execute_agent("B", "C2-ROTTEN-DYN", [SEC])
    new = captured[-1]

    assert len(captured) == 2
    assert new == legacy
    assert new["messages"][-1]["content"] == prompt
    assert new["options"]["seed"] == get_model().seed
    assert result == VALID
    assert attempts[0]["raw_output"] == CONTENT
    assert attempts[0]["generation_info"]["done_reason"] == "stop"
    json.dumps(attempts)
