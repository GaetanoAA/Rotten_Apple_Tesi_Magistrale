from __future__ import annotations

from core.schemas import AgentOutput


def build_agent_artifact(
    run_id: str,
    pair_id: str,
    step: int,
    agent_id: str,
    output: AgentOutput,
    parent_artifacts: list[dict],
    namespace: str | None = None,
) -> dict:

    parent_object_ids = [
        artifact["object_id"]
        for artifact in parent_artifacts
    ]

    inherited_root = None

    for artifact in parent_artifacts:
        if artifact.get("root_id") == "SEC-7421":
            inherited_root = "SEC-7421"
            break

    object_id = (
        f"mem://{namespace or run_id}/{agent_id}/decision/{step}"
    )

    return {
        "object_id": object_id,
        "run_id": run_id,
        "pair_id": pair_id,
        "step": step,
        "source_agent": agent_id,
        "verdict": output.verdict,
        "rationale_public": output.rationale_public,
        "summary": output.summary,
        "cited_object_ids": output.cited_object_ids,
        "decision_basis_ids": output.decision_basis_ids,
        "confidence_claimed": output.confidence_claimed,
        "parent_object_ids": parent_object_ids,
        "root_id": inherited_root,
    }