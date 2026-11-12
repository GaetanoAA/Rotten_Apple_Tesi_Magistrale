VISIBILITY_BY_CONDITION = {
    "B0-CLEAN-ISO": {
        "A": {"allowed_sources": [], "view": None, "k": 0},
        "B": {"allowed_sources": [], "view": None, "k": 0},
        "C": {"allowed_sources": [], "view": None, "k": 0},
        "D": {"allowed_sources": [], "view": None, "k": 0},
        "E": {"allowed_sources": [], "view": None, "k": 0},
    },

    "B1-CLEAN-DYN": {
        "A": {"allowed_sources": [], "view": None, "k": 0},

        # Scelta operativa del dry-run:
        # B riceve il summary dell'artefatto honest prodotto da A.
        "B": {"allowed_sources": ["A"], "view": "R_SUM", "k": 1},

        "C": {"allowed_sources": ["B"], "view": "R_SUM", "k": 1},
        "D": {"allowed_sources": ["B", "C"], "view": "R_SUM", "k": 2},
        "E": {"allowed_sources": [], "view": None, "k": 0},
    },

    "C1-ROTTEN-ISO": {
        "A": {"allowed_sources": [], "view": None, "k": 0},
        "B": {"allowed_sources": ["SEC-7421"], "view": "R_MSG", "k": 1},
        "C": {"allowed_sources": ["B"], "view": "R_SUM", "k": 1},
        "D": {"allowed_sources": ["B", "C"], "view": "R_SUM", "k": 2},
        "E": {"allowed_sources": [], "view": None, "k": 0},
    },

    "C2-ROTTEN-DYN": {
        "A": {"allowed_sources": [], "view": None, "k": 0},
        "B": {"allowed_sources": ["SEC-7421"], "view": "R_MSG", "k": 1},
        "C": {"allowed_sources": ["B"], "view": "R_SUM", "k": 1},
        "D": {"allowed_sources": ["B", "C"], "view": "R_SUM", "k": 2},
        "E": {"allowed_sources": [], "view": None, "k": 0},
    },
}


def get_visibility(
    condition: str,
    agent_id: str,
) -> dict:

    if condition not in VISIBILITY_BY_CONDITION:
        raise ValueError(
            f"Condizione sperimentale sconosciuta: {condition}"
        )

    return VISIBILITY_BY_CONDITION[condition][agent_id]