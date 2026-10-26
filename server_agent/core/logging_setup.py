import json
import logging
from datetime import datetime, timezone
from logging.handlers import WatchedFileHandler
from pathlib import Path


class _JsonFormatter(logging.Formatter):
    """Render each log record as a single JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(
    log_file: Path, level: str = "INFO", log_format: str = "text"
) -> logging.Logger:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("server_ai_agent")
    logger.setLevel(getattr(logging, level, logging.INFO))
    logger.handlers.clear()

    if log_format.lower() == "json":
        fmt: logging.Formatter = _JsonFormatter()
    else:
        fmt = logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
            "%Y-%m-%dT%H:%M:%S%z",
        )

    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    logger.addHandler(stream)

    # logrotate owns retention/compression; this handler notices its rename.
    file_handler = WatchedFileHandler(log_file)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    return logger
