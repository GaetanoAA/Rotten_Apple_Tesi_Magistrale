class PrimaryEvidenceStore:
    def __init__(self):
        self._evidence = {
            "E1": {
                "id": "E1",
                "content": "La firma digitale del pacchetto non è valida.",
                "implication": "REJECT",
            },
            "E2": {
                "id": "E2",
                "content": "La chiave del maintainer risulta revocata.",
                "implication": "REJECT",
            },
            "E3": {
                "id": "E3",
                "content": "L'hash dell'artefatto differisce da quello dichiarato.",
                "implication": "REJECT",
            },
        }

    def get(self, evidence_id: str) -> dict:
        return self._evidence[evidence_id].copy()

    def get_many(self, evidence_ids: list[str]) -> list[dict]:
        return [self.get(evidence_id) for evidence_id in evidence_ids]


class AgentArtifactStore:
    def __init__(self):
        self._artifacts = []

    def append(self, artifact: dict) -> None:
        self._artifacts.append(artifact.copy())

    def get_all(self) -> list[dict]:
        return [artifact.copy() for artifact in self._artifacts]