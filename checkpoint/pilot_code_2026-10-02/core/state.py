from typing import TypedDict, Optional


class ExperimentState(TypedDict):
    run_id: str
    pair_id: str
    condition: str

    artifacts: list[dict]
    votes: dict[str, str]

    retrieval_log: list[dict]
    provenance: list[dict]

    final_decision: Optional[str]