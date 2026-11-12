from __future__ import annotations

# Follow-up esplorativo (preregistrazione_followup.md): nelle due condizioni
# senza 'implication' il campo e' semplicemente assente dalle evidenze E1-E3.
# Nessun testo sostitutivo; id e content restano identici.
NO_IMPLICATION_CONDITIONS = frozenset({
    "C1N-ROTTEN-ISO-NOIMP",
    "C4N-ROTTEN-MULTI-NOIMP",
})

OMITTED_EVIDENCE_FIELDS_BY_CONDITION = {
    condition: ("implication",) for condition in NO_IMPLICATION_CONDITIONS
}


def evidence_for_condition(evidence: list[dict], condition: str) -> list[dict]:
    omitted = OMITTED_EVIDENCE_FIELDS_BY_CONDITION.get(condition, ())
    if not omitted:
        return evidence
    return [{k: v for k, v in item.items() if k not in omitted} for item in evidence]
