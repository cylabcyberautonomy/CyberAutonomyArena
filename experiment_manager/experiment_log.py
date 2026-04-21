from __future__ import annotations

import logging
from pathlib import Path

_loggers: dict[str, logging.Logger] = {}
_attacker_loggers: dict[str, logging.Logger] = {}
_fmt = logging.Formatter("%(asctime)s  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")


def init_logger(experiment_name: str, output_dir: Path) -> logging.Logger:
    """Create and register a file logger for an experiment. Call once when cfg is available."""
    if experiment_name in _loggers:
        return _loggers[experiment_name]
    log_path = output_dir / experiment_name / "experiment.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(f"experiment.{experiment_name}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(_file_handler(log_path))
    _loggers[experiment_name] = logger
    return logger


def get_logger(experiment_name: str) -> logging.Logger:
    """Look up an already-initialized experiment logger."""
    return _loggers.get(experiment_name, logging.getLogger(f"experiment.{experiment_name}"))


def init_attacker_logger(experiment_name: str, output_dir: Path) -> logging.Logger:
    """Create and register a file logger writing to attacker.log."""
    if experiment_name in _attacker_loggers:
        return _attacker_loggers[experiment_name]
    log_path = output_dir / experiment_name / "attacker.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(f"attacker.{experiment_name}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(_file_handler(log_path))
    _attacker_loggers[experiment_name] = logger
    return logger


def attacker_log(experiment_name: str, message: str) -> None:
    """Log a message to attacker.log."""
    _attacker_loggers.get(
        experiment_name, logging.getLogger(f"attacker.{experiment_name}")
    ).info(message)


def log(experiment_name: str, message: str) -> None:
    """Log a message to the experiment file."""
    get_logger(experiment_name).info(message)


def _file_handler(path: Path) -> logging.FileHandler:
    h = logging.FileHandler(path)
    h.setFormatter(_fmt)
    return h
