from config.visibility import get_visibility


def render_memory(
    agent_id: str,
    condition: str,
    artifacts: list[dict],
) -> str:

    if not artifacts:
        return "Nessuna memoria inter-agent disponibile."

    view = get_visibility(
        condition=condition,
        agent_id=agent_id,
    )["view"]

    rendered_blocks = []

    for artifact in artifacts:

        if view == "R_MSG":
            rendered_blocks.append(
                "\n".join([
                    f"object_id: {artifact.get('object_id', '')}",
                    f"source_agent: {artifact.get('source_agent', '')}",
                    (
                        "integrity_label: "
                        f"{artifact.get('integrity_label', '')}"
                    ),
                    f"content: {artifact.get('content', '')}",
                    (
                        "confidence_claimed: "
                        f"{artifact.get('confidence_claimed', '')}"
                    ),
                ])
            )

        elif view == "R_SUM":
            rendered_blocks.append(
                "\n".join([
                    f"object_id: {artifact.get('object_id', '')}",
                    f"source_agent: {artifact.get('source_agent', '')}",
                    f"summary: {artifact.get('summary', '')}",
                ])
            )

        else:
            raise ValueError(
                f"Vista non supportata per {agent_id}: {view}"
            )

    return "\n\n---\n\n".join(rendered_blocks)