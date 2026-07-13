"""Testes do logging estruturado (texto e JSON)."""

import json
import logging

from eigan.logging_setup import _JsonFormatter, _TextFormatter, get_logger


def _record(**extra) -> logging.LogRecord:
    r = logging.LogRecord("eigan.scan", logging.INFO, __file__, 1, "scan concluído", (), None)
    for k, v in extra.items():
        setattr(r, k, v)
    return r


def test_text_formatter_includes_structured_fields():
    out = _TextFormatter().format(_record(event="scan_done", scan_id=7, findings=3))
    assert "scan concluído" in out
    assert "event=scan_done" in out and "scan_id=7" in out and "findings=3" in out


def test_json_formatter_is_valid_json_with_fields():
    out = _JsonFormatter().format(_record(event="scan_start", job="job-1", targets="a,b"))
    obj = json.loads(out)
    assert obj["level"] == "INFO" and obj["logger"] == "eigan.scan"
    assert obj["msg"] == "scan concluído"
    assert obj["event"] == "scan_start" and obj["job"] == "job-1" and obj["targets"] == "a,b"


def test_get_logger_namespaced():
    assert get_logger("scan").name == "eigan.scan"
    assert get_logger("eigan.cognitive").name == "eigan.cognitive"
