"""Il logger non sovrascrive mai e non mescola run diverse."""

from __future__ import annotations

import json

import pytest

import core.logger as logger


def test_events_of_one_run_go_to_one_file(tmp_path, monkeypatch):
    monkeypatch.setenv(logger.RUN_DIR_ENV, str(tmp_path))
    logger.log_event("run_test_a", "RUN_START", {"x": 1})
    logger.log_event("run_test_a", "RUN_END", {"status": "COMPLETED"})
    lines = (tmp_path / "run_test_a.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["event_type"] for line in lines] == ["RUN_START", "RUN_END"]


def test_existing_file_is_never_reused_by_a_new_run(tmp_path, monkeypatch):
    monkeypatch.setenv(logger.RUN_DIR_ENV, str(tmp_path))
    (tmp_path / "run_test_b.jsonl").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(logger, "_OPENED_RUN_IDS", set())
    with pytest.raises(FileExistsError):
        logger.log_event("run_test_b", "RUN_START", {})
    assert (tmp_path / "run_test_b.jsonl").read_text(encoding="utf-8") == "{}\n"


def test_legacy_directory_when_not_configured(monkeypatch):
    monkeypatch.delenv(logger.RUN_DIR_ENV, raising=False)
    assert logger.get_log_dir() == logger.RESULTS_DIR
