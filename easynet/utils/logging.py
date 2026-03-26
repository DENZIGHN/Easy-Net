"""Logging setup for EasyNet."""

from __future__ import annotations

import logging
import sys
from pathlib import Path


def setup_logging(level: str = "INFO", log_file: str | None = None) -> logging.Logger:
    """Configure and return the root EasyNet logger."""
    logger = logging.getLogger("easynet")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Console handler with colored output
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    console.setFormatter(fmt)
    logger.addHandler(console)

    # File handler (optional)
    if log_file:
        log_path = Path(log_file).expanduser()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_path)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger
