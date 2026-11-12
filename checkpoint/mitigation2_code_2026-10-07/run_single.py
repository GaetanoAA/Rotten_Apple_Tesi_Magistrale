"""Esegue UNA run del pilot in un processo separato.

Viene lanciato da run_pilot.py: non eseguirlo a mano.
Stampa soltanto lo stato tecnico della run, mai voti o decisioni
(preregistrazione §4: nessuna analisi intermedia).

Codici di uscita: 0 COMPLETED, 1 FAILED, 3 TIMEOUT, 4 PRECHECK_FAILED
(Ollama non raggiungibile prima dell'avvio: nessun log, tentativo non contato),
130 INTERRUPTED.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pilot.phases import ALL_PHASES  # noqa: E402

EXIT_CODES = {
    "COMPLETED": 0,
    "FAILED": 1,
    "TIMEOUT": 3,
    "PRECHECK_FAILED": 4,
    "INTERRUPTED": 130,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", required=True, choices=ALL_PHASES)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--block", required=True, type=int)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--original-seed", required=True, type=int)
    parser.add_argument("--condition", required=True)
    parser.add_argument("--attempt", required=True, type=int)
    parser.add_argument("--call-timeout", required=True, type=float)
    parser.add_argument("--run-timeout", required=True, type=float)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--freeze-sha256", required=True)
    return parser


def pair_id_for(phase: str, block: int, seed: int, condition: str) -> str:
    family = "clean" if condition.startswith("B") else "attack"
    return f"{phase}_b{block:02d}_s{seed}_{family}"


def _find_in_chain(exc: BaseException, exc_type: type) -> BaseException | None:
    seen = set()
    current = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, exc_type):
            return current
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return None


def main(argv: list[str] | None = None, *, env_info_fn=None) -> int:
    args = build_parser().parse_args(argv)

    # Le variabili vanno impostate prima di eseguire il workflow:
    # logger ed executor le leggono a ogni chiamata.
    os.environ["ROTTEN_APPLE_RUN_DIR"] = args.run_dir
    os.environ["ROTTEN_APPLE_CALL_TIMEOUT_S"] = str(args.call_timeout)

    from config.model import MODEL_CONFIG
    from core.agent_executor import AgentCallTimeout
    from core.logger import log_event
    from core.workflow import build_workflow
    from pilot import envinfo

    MODEL_CONFIG["seed"] = args.seed

    pair_id = pair_id_for(args.phase, args.block, args.seed, args.condition)
    info_fn = env_info_fn or envinfo.ollama_info
    try:
        ollama = info_fn(MODEL_CONFIG["model"])
    except envinfo.OllamaUnavailable as exc:
        print(f"STATUS PRECHECK_FAILED ({exc})", flush=True)
        return EXIT_CODES["PRECHECK_FAILED"]
    runtime = envinfo.runtime_info()

    log_event(
        args.run_id,
        "RUN_START",
        {
            "run_id": args.run_id,
            "pair_id": pair_id,
            "condition": args.condition,
            "seed": args.seed,
            "phase": args.phase,
            "block": args.block,
            "original_seed": args.original_seed,
            "attempt": args.attempt,
            "model_config": MODEL_CONFIG.copy(),
            "call_timeout_s": args.call_timeout,
            "run_timeout_s": args.run_timeout,
            "plan_sha256": args.plan_sha256,
            "freeze_sha256": args.freeze_sha256,
            "code_sha256": envinfo.code_hashes(ROOT),
            "ollama_server_version": ollama.get("ollama_server_version"),
            "model_digest": ollama.get("model_digest"),
            "model_modified_at": ollama.get("model_modified_at"),
            "python_version": runtime["python_version"],
            "platform": runtime["platform"],
            "packages": runtime["packages"],
            "langgraph_version": runtime["packages"].get("langgraph"),
            "langchain_ollama_version": runtime["packages"].get("langchain-ollama"),
            "ollama_python_version": runtime["packages"].get("ollama"),
        },
    )

    initial_state = {
        "run_id": args.run_id,
        "pair_id": pair_id,
        "condition": args.condition,
        # Appendice, follow-up e mitigazione: identificativi neutri, uguali in
        # tutte le condizioni (preregistrazione_appendice.md,
        # preregistrazione_followup.md, preregistrazione_mitigazione.md).
        # Fasi precedenti: id della run.
        "memory_namespace": "run" if args.phase.startswith(("appendix_", "followup_", "mitigation_", "mitigation2_")) else None,
        "artifacts": [],
        "votes": {},
        "retrieval_log": [],
        "provenance": [],
        "final_decision": None,
    }

    try:
        result = build_workflow().invoke(initial_state)

    except BaseException as exc:
        if _find_in_chain(exc, AgentCallTimeout) is not None:
            status = "TIMEOUT"
        elif isinstance(exc, KeyboardInterrupt):
            status = "INTERRUPTED"
        else:
            status = "FAILED"

        log_event(
            args.run_id,
            "RUN_END",
            {
                "pair_id": pair_id,
                "seed": args.seed,
                "status": status,
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        print(f"STATUS {status}", flush=True)
        return EXIT_CODES[status]

    log_event(
        args.run_id,
        "RUN_END",
        {
            "pair_id": pair_id,
            "seed": args.seed,
            "status": "COMPLETED",
            "votes": result["votes"],
            "final_decision": result["final_decision"],
        },
    )
    print("STATUS COMPLETED", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
