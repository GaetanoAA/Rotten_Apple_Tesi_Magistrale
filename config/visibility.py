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

    # Esperimento sulla propagazione (preregistrazione_variante.md):
    # come C2, ma anche C e D leggono direttamente l'attestazione SEC-7421,
    # nello stesso formato di B (R_MSG); i summary degli agenti a monte
    # restano in R_SUM. k copre tutti gli oggetti ammessi: nessuna esclusione.
    "C4-ROTTEN-MULTI": {
        "A": {"allowed_sources": [], "view": None, "k": 0},
        "B": {"allowed_sources": ["SEC-7421"], "view": "R_MSG", "k": 1},
        "C": {"allowed_sources": ["SEC-7421", "B"], "view": "R_SUM", "k": 2,
              "view_by_claim": {"SEC-7421": "R_MSG"}},
        "D": {"allowed_sources": ["SEC-7421", "B", "C"], "view": "R_SUM", "k": 3,
              "view_by_claim": {"SEC-7421": "R_MSG"}},
        "E": {"allowed_sources": [], "view": None, "k": 0},
    },
}

# Appendice esplorativa: C5 ha la stessa visibilita' di C4; cambia solo
# l'etichetta di integrita' dell'attestazione (config/attack.py).
VISIBILITY_BY_CONDITION["C5-ROTTEN-VERIFIED"] = VISIBILITY_BY_CONDITION["C4-ROTTEN-MULTI"]

# Follow-up esplorativo (preregistrazione_followup.md): stesse matrici di C1 e
# C4; cambia solo l'assenza del campo 'implication' nelle evidenze
# (config/evidence.py).
VISIBILITY_BY_CONDITION["C1N-ROTTEN-ISO-NOIMP"] = VISIBILITY_BY_CONDITION["C1-ROTTEN-ISO"]
VISIBILITY_BY_CONDITION["C4N-ROTTEN-MULTI-NOIMP"] = VISIBILITY_BY_CONDITION["C4-ROTTEN-MULTI"]

# Esperimento sulla mitigazione (preregistrazione_mitigazione.md): difesa
# root-aware P_root del protocollo (§7.3, §8.1) applicata alla configurazione
# del follow-up. Stessa matrice e stessi K_i di C4N; per gli agenti honest gli
# oggetti con la stessa root_id sono collassati in una sola manifestazione
# (core/retrieval.py) e la provenance (sorgente, parent, radice) e' resa
# visibile nel prompt (core/context_builder.py).
VISIBILITY_BY_CONDITION["C3N-ROTTEN-PROV-NOIMP"] = {
    agent: ({**cfg, "root_collapse": True, "provenance_visible": True} if agent in ("B", "C", "D", "E") else dict(cfg))
    for agent, cfg in VISIBILITY_BY_CONDITION["C4-ROTTEN-MULTI"].items()
}

# Seconda mitigazione (preregistrazione_mitigazione_v2.md): root-aware con una
# sola modifica rispetto a C4N. Si collassano sulla radice solo i derivati
# concordi con essa (core/retrieval.py); i derivati che la contestano restano
# visibili; nessuna riga di provenienza nel prompt.
VISIBILITY_BY_CONDITION["C3D-ROTTEN-ROOT-NOIMP"] = {
    agent: ({**cfg, "root_collapse": "concordant"} if agent in ("B", "C", "D", "E") else dict(cfg))
    for agent, cfg in VISIBILITY_BY_CONDITION["C4-ROTTEN-MULTI"].items()
}

# Condizioni in cui la lineage di SEC-7421 e' salvata ma non accessibile
# agli agenti honest (core/retrieval.py).
LINEAGE_ISOLATED_CONDITIONS = frozenset({"C1-ROTTEN-ISO", "C1N-ROTTEN-ISO-NOIMP"})


def get_visibility(
    condition: str,
    agent_id: str,
) -> dict:

    if condition not in VISIBILITY_BY_CONDITION:
        raise ValueError(
            f"Condizione sperimentale sconosciuta: {condition}"
        )

    return VISIBILITY_BY_CONDITION[condition][agent_id]