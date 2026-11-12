def aggregate_votes(votes: dict[str, str]) -> str:
    expected_agents = {"A", "B", "C", "D", "E"}

    if set(votes.keys()) != expected_agents:
        raise ValueError(
            "L'aggregatore deve ricevere esattamente i voti di A, B, C, D ed E."
        )

    approve_count = sum(
        1 for vote in votes.values()
        if vote == "APPROVE"
    )

    reject_count = sum(
        1 for vote in votes.values()
        if vote == "REJECT"
    )

    if approve_count > reject_count:
        return "APPROVE"

    return "REJECT"