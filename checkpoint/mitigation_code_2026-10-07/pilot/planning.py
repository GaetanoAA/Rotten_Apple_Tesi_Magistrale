"""Logica di pianificazione del pilot: funzioni pure, senza I/O sul modello.

Stabilisce quale run eseguire dopo, applicando le regole della
preregistrazione (§4):
  - una combinazione blocco/seed/condizione COMPLETED non si ripete;
  - FAILED, TIMEOUT e INCOMPLETE contano come tentativi tecnici;
  - INTERRUPTED (interruzione volontaria con Ctrl+C) e PRECHECK_FAILED
    (Ollama non raggiungibile prima dell'avvio della run) non contano;
  - al massimo 1 + max_technical_reruns_per_run tentativi per run;
  - se C1 o C2 di un blocco esauriscono i tentativi, il blocco passa al
    primo seed di riserva libero, che ne eredita condizioni e ordine;
  - se li esaurisce B0 o B1, quella condizione viene esclusa e il blocco
    prosegue senza sostituzione.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pilot.phases import ALL_PHASES, kind_of

PRIMARY_CONDITIONS = ("C1-ROTTEN-ISO", "C2-ROTTEN-DYN", "C4-ROTTEN-MULTI", "C5-ROTTEN-VERIFIED",
                      "C1N-ROTTEN-ISO-NOIMP", "C4N-ROTTEN-MULTI-NOIMP", "C3N-ROTTEN-PROV-NOIMP")
CLEAN_CONDITIONS = ("B0-CLEAN-ISO", "B1-CLEAN-DYN")
PHASES = ALL_PHASES

COUNTED_FAILURES = {"FAILED", "TIMEOUT", "INCOMPLETE"}
NOT_COUNTED = {"INTERRUPTED", "PRECHECK_FAILED"}
KNOWN_STATUSES = {"COMPLETED"} | COUNTED_FAILURES | NOT_COUNTED


@dataclass(frozen=True)
class Record:
    run_id: str
    block: int
    seed: int
    condition: str
    attempt: int
    status: str


@dataclass(frozen=True)
class Action:
    block: int
    seed: int
    original_seed: int
    condition: str
    attempt: int


@dataclass
class Decision:
    action: Action | None = None
    done: bool = False
    stop_reason: str | None = None
    substitutions: list[tuple[int, int, int]] = field(default_factory=list)
    excluded: list[tuple[int, int, str]] = field(default_factory=list)


def blocks_for_phase(plan: dict, phase: str) -> list[dict]:
    kind = kind_of(phase)
    if kind == "smoke":
        smoke = plan["smoke"]
        return [{"block": 0, "seed": smoke["seed"], "order": list(smoke["conditions"])}]
    return [dict(block) for block in plan["blocks"]]


def planned_run_count(plan: dict, phase: str) -> int:
    return sum(len(block["order"]) for block in blocks_for_phase(plan, phase))


def records_from_sources(
    launches: list[dict],
    ledger_finishes: dict[str, str],
    log_run_end_status: dict[str, str],
) -> list[Record]:
    """Combina ledger del runner e RUN_END dei log in una lista di Record.

    Precedenza dello stato: RUN_END scritto nel log della run, poi l'esito
    registrato dal runner, altrimenti INCOMPLETE (ad esempio blackout).
    """

    records = []
    for launch in launches:
        run_id = launch["run_id"]
        status = (
            log_run_end_status.get(run_id)
            or ledger_finishes.get(run_id)
            or "INCOMPLETE"
        )
        if status not in KNOWN_STATUSES:
            status = "FAILED"
        records.append(
            Record(
                run_id=run_id,
                block=int(launch["block"]),
                seed=int(launch["seed"]),
                condition=launch["condition"],
                attempt=int(launch["attempt"]),
                status=status,
            )
        )
    return records


def next_action(plan: dict, phase: str, records: list[Record]) -> Decision:
    max_attempts = 1 + int(plan["max_technical_reruns_per_run"])
    reserves = list(plan["reserve_seeds"]) if kind_of(phase) == "attack" else []
    reserve_index = 0
    decision = Decision()

    for block in blocks_for_phase(plan, phase):
        seed = block["seed"]

        while True:
            replaced = False

            for condition in block["order"]:
                relevant = [
                    r for r in records
                    if r.block == block["block"]
                    and r.seed == seed
                    and r.condition == condition
                ]
                if any(r.status == "COMPLETED" for r in relevant):
                    continue

                failures = sum(r.status in COUNTED_FAILURES for r in relevant)
                if failures < max_attempts:
                    decision.action = Action(
                        block=block["block"],
                        seed=seed,
                        original_seed=block["seed"],
                        condition=condition,
                        attempt=len(relevant) + 1,
                    )
                    return decision

                if condition in PRIMARY_CONDITIONS:
                    if reserve_index >= len(reserves):
                        decision.stop_reason = (
                            f"blocco {block['block']}: tentativi esauriti e "
                            "nessun seed di riserva disponibile"
                        )
                        return decision
                    new_seed = reserves[reserve_index]
                    reserve_index += 1
                    decision.substitutions.append((block["block"], seed, new_seed))
                    seed = new_seed
                    replaced = True
                    break

                decision.excluded.append((block["block"], seed, condition))

            if not replaced:
                break

    decision.done = True
    return decision
