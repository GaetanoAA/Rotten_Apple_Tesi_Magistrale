"""Configurazione comune dei test: nessun test invoca Ollama.

Il modello viene sostituito da FakeModel, che restituisce output validi
costruiti dalle regole del progetto e registra i prompt ricevuti.
"""

from __future__ import annotations

import json
import re
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

AGENT_RE = re.compile(r"Sei l'agente (\w)")
OBJECT_RE = re.compile(r"^object_id:\s*(\S+)\s*$", re.MULTILINE)


class _NotSerializable:
    def __str__(self):
        return "oggetto-non-serializzabile"


def fake_llm_result(text: str):
    generation = SimpleNamespace(
        message=SimpleNamespace(content=text),
        text=text,
        generation_info={"done_reason": "stop", "eval_count": 42, "extra": _NotSerializable()},
    )
    return SimpleNamespace(generations=[[generation]])


def default_output(agent_id: str, prompt: str):
    from config.agents import AGENT_CONFIG
    from core.schemas import AgentOutput

    evidence = list(AGENT_CONFIG[agent_id]["primary_evidence"])
    memory_ids = OBJECT_RE.findall(prompt)
    cited = evidence or memory_ids
    return AgentOutput(
        verdict="REJECT",
        rationale_public=f"Motivazione di prova dell'agente {agent_id}.",
        summary=f"Sintesi di prova dell'agente {agent_id}.",
        cited_object_ids=cited,
        decision_basis_ids=evidence,
        confidence_claimed=0.9,
    )


class FakeStructured:
    def __init__(self, owner):
        self.owner = owner

    def invoke(self, prompt, config=None):
        owner = self.owner
        owner.prompts.append(prompt)
        owner.threads.append(threading.current_thread() is threading.main_thread())
        agent_id = AGENT_RE.search(prompt).group(1)
        call_index = len(owner.prompts) - 1
        result = owner.behaviour(agent_id, prompt, call_index)
        if isinstance(result, (int, float)) and not isinstance(result, bool):
            time.sleep(result)
            result = default_output(agent_id, prompt)
        for callback in (config or {}).get("callbacks", []):
            text = json.dumps(result.model_dump()) if hasattr(result, "model_dump") else str(result)
            callback.on_llm_end(fake_llm_result(text))
        if isinstance(result, BaseException):
            raise result
        return result


class FakeModel:
    def __init__(self, behaviour=None):
        self.behaviour = behaviour or (lambda agent_id, prompt, i: default_output(agent_id, prompt))
        self.prompts: list[str] = []
        self.threads: list[bool] = []

    def with_structured_output(self, schema):
        return FakeStructured(self)


@pytest.fixture
def fake_model(monkeypatch):
    """Restituisce una funzione che installa un FakeModel con il comportamento dato."""

    import core.agent_executor as executor

    def install(behaviour=None):
        model = FakeModel(behaviour)
        monkeypatch.setattr(executor, "get_model", lambda: model)
        return model

    return install


@pytest.fixture
def fake_ollama_info():
    plan = json.loads((PROJECT_ROOT / "config" / "pilot_plan.json").read_text(encoding="utf-8"))

    def info(model_name):
        return {
            "ollama_server_version": plan["model"]["ollama_server_version"],
            "model_digest": plan["model"]["digest"],
            "model_modified_at": "2026-10-02T04:07:12+02:00",
        }

    return info
