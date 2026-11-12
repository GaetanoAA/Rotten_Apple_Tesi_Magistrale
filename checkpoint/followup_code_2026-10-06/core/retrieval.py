from config.visibility import LINEAGE_ISOLATED_CONDITIONS, get_visibility


def retrieve_artifacts(
    agent_id: str,
    condition: str,
    artifacts: list[dict],
) -> tuple[list[dict], dict]:

    config = get_visibility(
        condition=condition,
        agent_id=agent_id,
    )

    allowed_sources = config["allowed_sources"]
    k = config["k"]

    ledger = {
        "agent_id": agent_id,
        "condition": condition,
        "candidate_artifact_ids": [
            artifact.get("object_id")
            for artifact in artifacts
        ],
        "eligible_artifact_ids": [],
        "excluded_artifacts": [],
        "selected_artifact_ids": [],
    }

    if k == 0:
        for artifact in artifacts:
            ledger["excluded_artifacts"].append(
                {
                    "object_id": artifact.get("object_id"),
                    "reason": (
                        "K_i=0 / nessuna memoria "
                        "inter-agent consentita"
                    ),
                }
            )

        return [], ledger

    eligible = []

    for artifact in artifacts:

        object_id = artifact.get("object_id")
        source_agent = artifact.get("source_agent")
        claim_id = artifact.get("claim_id")

        # In C1 la falsa attestazione viene salvata,
        # ma SEC-7421 e tutti i suoi discendenti
        # non sono accessibili agli honest agent.
        if condition in LINEAGE_ISOLATED_CONDITIONS:
            if (
                claim_id == "SEC-7421"
                or artifact.get("root_id") == "SEC-7421"
            ):
                ledger["excluded_artifacts"].append(
                    {
                        "object_id": object_id,
                        "reason": (
                            "lineage SEC-7421 esclusa in C1"
                        ),
                    }
                )
                continue

        # Accesso diretto a SEC-7421 per B nella C2.
        if (
            "SEC-7421" in allowed_sources
            and claim_id == "SEC-7421"
        ):
            eligible.append(artifact)
            ledger["eligible_artifact_ids"].append(
                object_id
            )
            continue

        # Accesso agli artefatti decisionali prodotti
        # dagli agenti ammessi dalla matrice.
        if source_agent in allowed_sources:
            eligible.append(artifact)
            ledger["eligible_artifact_ids"].append(
                object_id
            )
            continue

        ledger["excluded_artifacts"].append(
            {
                "object_id": object_id,
                "reason": (
                    "non consentito dalla matrice di visibilità"
                ),
            }
        )

    eligible.sort(
        key=lambda x: (
            -x.get("step", 0),
            x.get("object_id", ""),
        )
    )

    selected = eligible[:k]

    ledger["selected_artifact_ids"] = [
        artifact["object_id"]
        for artifact in selected
    ]

    return selected, ledger