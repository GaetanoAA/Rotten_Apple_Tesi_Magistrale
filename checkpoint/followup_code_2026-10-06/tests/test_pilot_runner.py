"""Runner: ripresa, timeout per run, pause di sicurezza, controlli su Ollama.

Il processo figlio e' sostituito da uno script finto che scrive un log
minimo: nessuna chiamata al modello.
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

from pilot import runner

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REAL_PLAN = json.loads((PROJECT_ROOT / "config" / "pilot_plan.json").read_text(encoding="utf-8"))

FAKE_CHILD = textwrap.dedent(
    """
    import json, sys, time
    args = json.loads(sys.argv[1])
    mode = sys.argv[2]
    path = f"{args['run_dir']}/{args['run_id']}.jsonl"
    def write(event_type, data):
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"run_id": args["run_id"], "event_type": event_type, "data": data}) + "\\n")
    write("RUN_START", {"seed": int(args["seed"]), "condition": args["condition"]})
    if mode == "sleep":
        time.sleep(30)
    if mode == "fail":
        write("RUN_END", {"status": "FAILED"})
        print("STATUS FAILED"); sys.exit(1)
    write("RUN_END", {"status": "COMPLETED", "votes": {"A": "APPROVE"}})
    print("STATUS COMPLETED"); sys.exit(0)
    """
)


@pytest.fixture
def project(tmp_path):
    plan = json.loads(json.dumps(REAL_PLAN))
    plan["timeouts"]["per_run_seconds"] = 3
    child = tmp_path / "fake_child.py"
    child.write_text(FAKE_CHILD, encoding="utf-8")
    return tmp_path, plan, child


def command_for(child, mode):
    return lambda root, args: [sys.executable, str(child), json.dumps(args), mode]


def good_info(plan):
    return lambda name: {"model_digest": plan["model"]["digest"],
                         "ollama_server_version": plan["model"]["ollama_server_version"]}


def run(project, mode, **kwargs):
    root, plan, child = project
    output: list[str] = []
    code = runner.run_loop(
        root, "pilot_smoke", plan=plan, plan_sha256="p" * 64, freeze_sha256="f" * 64,
        ollama_info_fn=kwargs.pop("info", good_info(plan)), child_command=command_for(child, mode),
        out=output.append, **kwargs,
    )
    return code, output


def test_smoke_runs_all_four_conditions_and_never_prints_votes(project):
    code, output = run(project, "ok")
    assert code == 0
    assert output[-1] == "FASE pilot_smoke COMPLETATA."
    text = "\n".join(output)
    assert "APPROVE" not in text and "REJECT" not in text
    records = runner.scan_records(project[0] / "runs" / "pilot_smoke")
    assert sorted(r.condition for r in records) == sorted(REAL_PLAN["smoke"]["conditions"])
    assert all(r.status == "COMPLETED" for r in records)


def test_resume_continues_where_it_stopped(project):
    code, _ = run(project, "ok", max_runs=1)
    assert code == 0
    assert len(runner.scan_records(project[0] / "runs" / "pilot_smoke")) == 1
    code, _ = run(project, "ok")
    assert code == 0
    records = runner.scan_records(project[0] / "runs" / "pilot_smoke")
    assert len(records) == 4 and len({r.condition for r in records}) == 4


def test_run_timeout_is_recorded_and_two_failures_pause_the_runner(project):
    code, output = run(project, "sleep")
    assert code == 2
    assert any(line.startswith("PAUSA") for line in output)
    run_dir = project[0] / "runs" / "pilot_smoke"
    records = runner.scan_records(run_dir)
    assert [r.status for r in records] == ["TIMEOUT", "TIMEOUT"]
    assert [r.attempt for r in records] == [1, 2]
    for record in records:
        end = [json.loads(line) for line in (run_dir / f"{record.run_id}.jsonl").read_text().splitlines()][-1]
        assert end["event_type"] == "RUN_END" and end["data"]["written_by"] == "runner"


def test_digest_mismatch_stops_before_launching(project):
    code, output = run(project, "ok", info=lambda name: {"model_digest": "x", "ollama_server_version": "0.35.0"})
    assert code == 2 and "digest" in output[-1]
    assert not (project[0] / "runs" / "pilot_smoke" / runner.LEDGER_NAME).exists()


def test_dry_run_launches_nothing(project):
    code, output = run(project, "ok", dry_run=True)
    assert code == 0 and "simulazione" in output[-1]
    assert not (project[0] / "runs" / "pilot_smoke" / runner.LEDGER_NAME).exists()


def test_verify_freeze_detects_changes(tmp_path):
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "a.py").write_text("x = 1\n", encoding="utf-8")
    freeze = {"code_sha256": runner.envinfo.code_hashes(tmp_path), "packages": {}}
    assert runner.verify_freeze(tmp_path, freeze) == []
    (tmp_path / "core" / "a.py").write_text("x = 2\n", encoding="utf-8")
    (tmp_path / "core" / "b.py").write_text("y = 1\n", encoding="utf-8")
    problems = runner.verify_freeze(tmp_path, freeze)
    assert any("modificato" in p for p in problems) and any("nuovo" in p for p in problems)
