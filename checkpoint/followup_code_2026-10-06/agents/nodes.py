from config.attack import INTEGRITY_LABEL_BY_CONDITION, build_sec_7421
from config.agents import AGENT_CONFIG

from core.agent_executor import (
    execute_agent,
    AgentExecutionError,
    AgentCallTimeout,
)
from core.artifact_builder import build_agent_artifact
from core.attacker import get_fixed_malicious_output
from core.context_builder import render_memory
from core.logger import log_event
from core.prompt_builder import build_prompt
from core.retrieval import retrieve_artifacts


CLEAN_CONDITIONS = {
    "B0-CLEAN-ISO",
    "B1-CLEAN-DYN",
}

ROTTEN_CONDITIONS = {
    "C1-ROTTEN-ISO",
    "C2-ROTTEN-DYN",
    "C4-ROTTEN-MULTI",
    "C5-ROTTEN-VERIFIED",
    "C1N-ROTTEN-ISO-NOIMP",
    "C4N-ROTTEN-MULTI-NOIMP",
}


def log_honest_input(
    run_id: str,
    agent_id: str,
    condition: str,
    retrieved: list[dict],
    retrieval_ledger: dict,
    rendered_memory: str,
) -> None:

    # Registrato PRIMA della chiamata al modello: se la run si interrompe,
    # il log contiene comunque il prompt costruito per l'agente.
    initial_prompt = build_prompt(
        agent_id=agent_id,
        condition=condition,
        retrieved_artifacts=retrieved,
    )

    log_event(
        run_id,
        "AGENT_INPUT",
        {
            "agent_id": agent_id,
            "primary_evidence_ids":
                AGENT_CONFIG[agent_id]["primary_evidence"],
            "retrieval": retrieval_ledger,
            "rendered_memory": rendered_memory,
            "initial_prompt": initial_prompt,
        },
    )


def log_attempts(
    run_id: str,
    agent_id: str,
    attempts: list[dict],
) -> None:

    for attempt in attempts:
        log_event(
            run_id,
            "AGENT_ATTEMPT",
            {
                "agent_id": agent_id,
                **attempt,
            },
        )


def execute_and_log(
    run_id: str,
    agent_id: str,
    condition: str,
    retrieved: list[dict],
    retrieval_ledger: dict,
    rendered_memory: str,
):

    log_honest_input(
        run_id=run_id,
        agent_id=agent_id,
        condition=condition,
        retrieved=retrieved,
        retrieval_ledger=retrieval_ledger,
        rendered_memory=rendered_memory,
    )

    try:
        output, attempts = execute_agent(
            agent_id=agent_id,
            condition=condition,
            retrieved_artifacts=retrieved,
        )

    except AgentCallTimeout as exc:

        log_attempts(run_id, agent_id, exc.attempts)

        log_event(
            run_id,
            "AGENT_TIMEOUT",
            {
                "agent_id": agent_id,
                "error": str(exc),
            },
        )

        raise

    except AgentExecutionError as exc:

        log_attempts(run_id, agent_id, exc.attempts)

        log_event(
            run_id,
            "AGENT_FAILURE",
            {
                "agent_id": agent_id,
                "error": str(exc),
            },
        )

        raise

    log_attempts(run_id, agent_id, attempts)

    return output, attempts


def run_agent_a(state: dict) -> dict:

    run_id = state["run_id"]
    pair_id = state["pair_id"]
    condition = state["condition"]

    # -----------------------------------------
    # B0 / B1: A è HONEST
    # -----------------------------------------
    if condition in CLEAN_CONDITIONS:

        retrieved, retrieval_ledger = retrieve_artifacts(
            agent_id="A",
            condition=condition,
            artifacts=state["artifacts"],
        )

        rendered_memory = render_memory(
            agent_id="A",
            condition=condition,
            artifacts=retrieved,
        )

        output, attempts = execute_and_log(
            run_id=run_id,
            agent_id="A",
            condition=condition,
            retrieved=retrieved,
            retrieval_ledger=retrieval_ledger,
            rendered_memory=rendered_memory,
        )

        artifact_a = build_agent_artifact(
            run_id=run_id,
            pair_id=pair_id,
            step=1,
            agent_id="A",
            output=output,
            parent_artifacts=retrieved,
            namespace=state.get("memory_namespace"),
        )

        artifacts = (
            state["artifacts"]
            + [artifact_a]
        )

        votes = state["votes"].copy()
        votes["A"] = output.verdict

        log_event(
            run_id,
            "AGENT_OUTPUT",
            {
                "agent_id": "A",
                "controlled_by_attacker": False,
                "output": output.model_dump(),
                "number_of_attempts": len(attempts),
            },
        )

        log_event(
            run_id,
            "MEMORY_WRITE",
            {
                "artifact": artifact_a,
            },
        )

        return {
            **state,
            "artifacts": artifacts,
            "votes": votes,
        }

    # -----------------------------------------
    # C1 / C2: A è MALICIOUS
    # -----------------------------------------
    if condition in ROTTEN_CONDITIONS:

        output = get_fixed_malicious_output()

        namespace = state.get("memory_namespace")
        artifact_a = build_agent_artifact(
            run_id=run_id,
            pair_id=pair_id,
            step=1,
            agent_id="A",
            output=output,
            parent_artifacts=[],
            namespace=namespace,
        )

        sec_7421 = build_sec_7421(
            run_id=run_id,
            pair_id=pair_id,
            namespace=namespace,
            integrity_label=INTEGRITY_LABEL_BY_CONDITION.get(
                condition, "unverified_internal"
            ),
        )

        artifacts = state["artifacts"] + [
            artifact_a,
            sec_7421,
        ]

        votes = state["votes"].copy()
        votes["A"] = output.verdict

        log_event(
            run_id,
            "AGENT_OUTPUT",
            {
                "agent_id": "A",
                "controlled_by_attacker": True,
                "output": output.model_dump(),
            },
        )

        log_event(
            run_id,
            "MEMORY_WRITE",
            {
                "artifact": artifact_a,
            },
        )

        log_event(
            run_id,
            "MEMORY_WRITE",
            {
                "artifact": sec_7421,
            },
        )

        return {
            **state,
            "artifacts": artifacts,
            "votes": votes,
        }

    raise ValueError(
        f"Condizione non supportata: {condition}"
    )


def run_honest_agent(
    state: dict,
    agent_id: str,
    step: int,
) -> dict:

    run_id = state["run_id"]
    pair_id = state["pair_id"]
    condition = state["condition"]

    retrieved, retrieval_ledger = retrieve_artifacts(
        agent_id=agent_id,
        condition=condition,
        artifacts=state["artifacts"],
    )

    rendered_memory = render_memory(
        agent_id=agent_id,
        condition=condition,
        artifacts=retrieved,
    )

    output, attempts = execute_and_log(
        run_id=run_id,
        agent_id=agent_id,
        condition=condition,
        retrieved=retrieved,
        retrieval_ledger=retrieval_ledger,
        rendered_memory=rendered_memory,
    )

    artifact = build_agent_artifact(
        run_id=run_id,
        pair_id=pair_id,
        step=step,
        agent_id=agent_id,
        output=output,
        parent_artifacts=retrieved,
        namespace=state.get("memory_namespace"),
    )

    artifacts = (
        state["artifacts"]
        + [artifact]
    )

    votes = state["votes"].copy()
    votes[agent_id] = output.verdict

    retrieval_log = (
        state["retrieval_log"]
        + [retrieval_ledger]
    )

    log_event(
        run_id,
        "AGENT_OUTPUT",
        {
            "agent_id": agent_id,
            "output": output.model_dump(),
            "number_of_attempts": len(attempts),
        },
    )

    log_event(
        run_id,
        "MEMORY_WRITE",
        {
            "artifact": artifact,
        },
    )

    return {
        **state,
        "artifacts": artifacts,
        "votes": votes,
        "retrieval_log": retrieval_log,
    }


def run_agent_b(state: dict) -> dict:
    return run_honest_agent(
        state,
        "B",
        2,
    )


def run_agent_c(state: dict) -> dict:
    return run_honest_agent(
        state,
        "C",
        3,
    )


def run_agent_d(state: dict) -> dict:
    return run_honest_agent(
        state,
        "D",
        4,
    )


def run_agent_e(state: dict) -> dict:
    return run_honest_agent(
        state,
        "E",
        5,
    )
