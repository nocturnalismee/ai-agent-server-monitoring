import logging
from logging.handlers import WatchedFileHandler
from pathlib import Path


def setup_logging(log_file: Path, level: str = "INFO") -> logging.Logger:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("server_ai_agent")
    logger.setLevel(getattr(logging, level, logging.INFO))
    logger.handlers.clear()

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
