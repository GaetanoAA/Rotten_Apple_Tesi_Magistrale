"""Fasi di raccolta e file associati (pilot ed esperimento principale).

Ogni fase ha la forma <stadio>_<tipo>: lo stadio sceglie piano, congelamento
e preregistrazione; il tipo distingue la prova tecnica (smoke) dalla
raccolta vera e propria (attack).
"""

from __future__ import annotations

STAGES = {
    "pilot": {
        "plan": "config/pilot_plan.json",
        "freeze": "config/pilot_freeze.json",
        "prereg": "documentazione/preregistrazione_pilot.md",
    },
    "main": {
        "plan": "config/main_plan.json",
        "freeze": "config/main_freeze.json",
        "prereg": "documentazione/preregistrazione_principale.md",
    },
    "variant": {
        "plan": "config/variant_plan.json",
        "freeze": "config/variant_freeze.json",
        "prereg": "documentazione/preregistrazione_variante.md",
    },
}
KINDS = ("smoke", "attack")
ALL_PHASES = tuple(f"{stage}_{kind}" for stage in STAGES for kind in KINDS)


def split_phase(phase: str) -> tuple[str, str]:
    stage, _, kind = phase.partition("_")
    if stage not in STAGES or kind not in KINDS:
        raise ValueError(f"fase non valida: {phase!r}")
    return stage, kind


def stage_of(phase: str) -> str:
    return split_phase(phase)[0]


def kind_of(phase: str) -> str:
    return split_phase(phase)[1]


def stage_paths(stage: str) -> dict:
    return STAGES[stage]
