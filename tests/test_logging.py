import json
import logging

from server_agent.core.logging_setup import setup_logging


def _flush(logger: logging.Logger) -> None:
    for handler in logger.handlers:
        handler.flush()


def _close(logger: logging.Logger) -> None:
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)


def _last_line(log_file):
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    return lines[-1]


def test_json_logging_emits_one_object_per_line(tmp_path):
    log_file = tmp_path / "agent.log"
    logger = setup_logging(log_file, "INFO", "json")
    try:
        logger.info("hello %s", "world")
        _flush(logger)
        payload = json.loads(_last_line(log_file))
        assert payload["level"] == "INFO"
        assert payload["logger"] == "server_ai_agent"
        assert payload["message"] == "hello world"
        assert payload["ts"].endswith("+00:00")
    finally:
        _close(logger)


def test_json_logging_includes_traceback(tmp_path):
    log_file = tmp_path / "agent.log"
    logger = setup_logging(log_file, "INFO", "json")
    try:
        try:
            raise ValueError("boom")
        except ValueError:
            logger.exception("failed")
        _flush(logger)
        payload = json.loads(_last_line(log_file))
        assert payload["message"] == "failed"
        assert "ValueError: boom" in payload["exc_info"]
    finally:
        _close(logger)


def test_text_logging_is_not_json(tmp_path):
    log_file = tmp_path / "agent.log"
    logger = setup_logging(log_file, "INFO", "text")
    try:
        logger.info("plain text")
        _flush(logger)
        line = _last_line(log_file)
        assert "plain text" in line
        try:
            json.loads(line)
        except json.JSONDecodeError:
            pass
        else:
            raise AssertionError("text format should not be valid JSON")
    finally:
        _close(logger)
