import json
import os
import threading
import time

from langchain_core.callbacks import BaseCallbackHandler

from config.agents import AGENT_CONFIG
from config.runtime import MAX_RETRIES

from core.model_client import get_model
from core.schemas import AgentOutput
from core.prompt_builder import build_prompt


# Timeout per singola chiamata al modello, in secondi.
# Impostato dal runner del pilot; se assente la chiamata non ha limite
# (comportamento identico al dry run).
CALL_TIMEOUT_ENV = "ROTTEN_APPLE_CALL_TIMEOUT_S"


class AgentExecutionError(Exception):
    def __init__(
        self,
        message: str,
        attempts: list[dict],
    ):
        super().__init__(message)
        self.attempts = attempts


class AgentCallTimeout(Exception):
    """Una chiamata al modello ha superato il timeout: guasto tecnico.

    Non attiva il retry di validazione: la run viene chiusa come TIMEOUT.
    """

    def __init__(
        self,
        message: str,
        attempts: list[dict],
    ):
        super().__init__(message)
        self.attempts = attempts


class _CallTimedOut(Exception):
    pass


class _RawOutputCapture(BaseCallbackHandler):
    """Registra il testo grezzo restituito dal modello.

    Un callback non modifica la richiesta inviata a Ollama: osserva soltanto
    la risposta prima che venga interpretata dallo schema Pydantic.
    """

    def __init__(self):
        self.raw_output = None
        self.generation_info = None

    def on_llm_end(self, response, **kwargs):
        try:
            generation = response.generations[0][0]
            message = getattr(generation, "message", None)
            self.raw_output = (
                message.content
                if message is not None
                else generation.text
            )
            self.generation_info = generation.generation_info
        except Exception as exc:
            self.raw_output = f"<raw capture failed: {exc!r}>"


def _json_safe(value):
    if value is None:
        return None
    return json.loads(
        json.dumps(
            value,
            ensure_ascii=False,
            default=lambda obj: (
                obj.model_dump()
                if hasattr(obj, "model_dump")
                else str(obj)
            ),
        )
    )


def _call_timeout_seconds():
    configured = os.environ.get(CALL_TIMEOUT_ENV)
    return float(configured) if configured else None


def _invoke(structured_model, prompt, capture, timeout_s):
    config = {"callbacks": [capture]}

    if timeout_s is None:
        return structured_model.invoke(prompt, config=config)

    box = {}

    def target():
        try:
            box["result"] = structured_model.invoke(prompt, config=config)
        except BaseException as exc:
            box["error"] = exc

    # Thread daemon: se la chiamata non termina, il processo della run
    # puo' comunque chiudersi dopo aver registrato il TIMEOUT.
    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(timeout_s)

    if worker.is_alive():
        raise _CallTimedOut()
    if "error" in box:
        raise box["error"]
    return box["result"]


def execute_agent(
    agent_id: str,
    condition: str,
    retrieved_artifacts: list[dict],
) -> tuple[AgentOutput, list[dict]]:

    model = get_model()

    structured_model = model.with_structured_output(
        AgentOutput
    )

    base_prompt = build_prompt(
        agent_id=agent_id,
        condition=condition,
        retrieved_artifacts=retrieved_artifacts,
    )

    allowed_ids = set(
        AGENT_CONFIG[agent_id]["primary_evidence"]
    )

    allowed_ids.update(
        artifact["object_id"]
        for artifact in retrieved_artifacts
    )

    timeout_s = _call_timeout_seconds()

    attempts = []

    for attempt_number in range(MAX_RETRIES + 1):

        if attempt_number == 0:
            current_prompt = base_prompt

        else:
            current_prompt = (
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

        capture = _RawOutputCapture()
        started = time.perf_counter()

        try:
            result = _invoke(
                structured_model,
                current_prompt,
                capture,
                timeout_s,
            )

        except _CallTimedOut:
            attempts.append(
                {
                    "attempt": attempt_number + 1,
                    "prompt": current_prompt,
                    "valid": False,
                    "error_type": "AgentCallTimeout",
                    "error": (
                        f"nessuna risposta entro {timeout_s} secondi"
                    ),
                    "latency_s": round(time.perf_counter() - started, 3),
                    "raw_output": capture.raw_output,
                    "generation_info": _json_safe(capture.generation_info),
                }
            )

            raise AgentCallTimeout(
                (
                    f"Agente {agent_id}: timeout della chiamata "
                    f"({timeout_s} s) al tentativo {attempt_number + 1}."
                ),
                attempts,
            )

        except Exception as exc:
            attempts.append(
                {
                    "attempt": attempt_number + 1,
                    "prompt": current_prompt,
                    "valid": False,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "latency_s": round(time.perf_counter() - started, 3),
                    "raw_output": capture.raw_output,
                    "generation_info": _json_safe(capture.generation_info),
                }
            )

            if attempt_number == MAX_RETRIES:
                raise AgentExecutionError(
                    (
                        f"Agente {agent_id}: errore del modello "
                        f"dopo {MAX_RETRIES + 1} tentativi."
                    ),
                    attempts,
                ) from exc

            continue

        latency_s = round(time.perf_counter() - started, 3)

        cited_ids = set(
            result.cited_object_ids
        )

        basis_ids = set(
            result.decision_basis_ids
        )

        invalid_cited = (
            cited_ids - allowed_ids
        )

        invalid_basis = (
            basis_ids - allowed_ids
        )

        valid = (
            not invalid_cited
            and not invalid_basis
        )

        attempts.append(
            {
                "attempt": attempt_number + 1,
                "prompt": current_prompt,
                "valid": valid,
                "output": result.model_dump(),
                "invalid_cited_object_ids":
                    sorted(invalid_cited),
                "invalid_decision_basis_ids":
                    sorted(invalid_basis),
                "latency_s": latency_s,
                "raw_output": capture.raw_output,
                "generation_info": _json_safe(capture.generation_info),
            }
        )

        if valid:
            return result, attempts

        if attempt_number == MAX_RETRIES:
            raise AgentExecutionError(
                (
                    f"Agente {agent_id}: output non valido "
                    f"dopo {MAX_RETRIES + 1} tentativi."
                ),
                attempts,
            )

    raise AgentExecutionError(
        f"Errore inatteso nell'agente {agent_id}.",
        attempts,
    )
