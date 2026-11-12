from config.visibility import get_visibility


def render_memory(
    agent_id: str,
    condition: str,
    artifacts: list[dict],
) -> str:

    if not artifacts:
        return "Nessuna memoria inter-agent disponibile."

    config = get_visibility(
        condition=condition,
        agent_id=agent_id,
    )
    default_view = config["view"]
    view_by_claim = config.get("view_by_claim", {})
    provenance_visible = config.get("provenance_visible", False)

    rendered_blocks = []

    for artifact in artifacts:

        view = view_by_claim.get(artifact.get("claim_id"), default_view)

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

        # Provenance visibile (P_root, preregistrazione_mitigazione.md):
        # sorgente gia' presente; si aggiungono parent, radice informativa e
        # gli oggetti collassati con la stessa radice. Nessuna etichetta
        # 'poison'.
        if provenance_visible:
            parents = artifact.get("parent_object_ids") or []
            collapsed = artifact.get("_collapsed_same_root") or []
            lines = [
                "root_id: "
                + (
                    artifact.get("_root_object_id")
                    or artifact.get("root_id")
                    or artifact.get("object_id", "")
                ),
                "parent_object_ids: "
                + (", ".join(parents) if parents else "nessuno"),
            ]
            if collapsed:
                sources = ", ".join(
                    sorted({c.get("source_agent", "") for c in collapsed})
                )
                lines.append(
                    "oggetti_derivati_dalla_stessa_radice: "
                    f"{len(collapsed)} (source_agent: {sources}), "
                    "non mostrati"
                )
            rendered_blocks[-1] = rendered_blocks[-1] + "\n" + "\n".join(lines)

    return "\n\n---\n\n".join(rendered_blocks)