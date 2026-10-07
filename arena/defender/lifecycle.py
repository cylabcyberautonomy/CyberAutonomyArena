"""DefenderLifecycle — the arena<->defender handshake channel, symmetric with attacker/lifecycle.py."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional


class DefenderCommand(str, Enum):
    """Arena -> defender commands that drive each phase."""
    START_SETUP = "StartSetup"
    START = "Start"
    STOP = "Stop"


class DefenderSignal(str, Enum):
    """Defender -> arena signals, recorded on the Experiment."""
    SETUP_STARTED = "SetupStarted"
    READY = "Ready"
    RUNNING = "Running"
    STOPPING = "Stopping"
    STOPPED = "Stopped"
    FAILED = "Failed"


class DefenderLifecycleError(RuntimeError):
    """Raised from wait() when the defender emitted FAILED before the awaited signal."""


class DefenderLifecycle:
    """Symmetric with AttackerLifecycle."""

    def __init__(self, on_emit: Optional[Callable[["DefenderSignal", Optional[str]], None]] = None,
                 on_command: Optional[Callable[["DefenderCommand"], None]] = None):
        self._on_emit = on_emit
        self._on_command = on_command
        self._history: list[DefenderSignal] = []
        self._commands: list[DefenderCommand] = []
        self._status: Optional[DefenderSignal] = None
        self._error: Optional[str] = None
        self._cond = asyncio.Condition()

    @property
    def commands(self) -> list["DefenderCommand"]:
        return list(self._commands)

    @property
    def status(self) -> Optional[DefenderSignal]:
        return self._status

    @property
    def history(self) -> list[DefenderSignal]:
        return list(self._history)

    async def send(self, command: "DefenderCommand") -> None:
        """Arena -> defender: record + announce a command that drives the next phase."""
        async with self._cond:
            self._commands.append(command)
            if self._on_command is not None:
                self._on_command(command)
            self._cond.notify_all()

    async def emit(self, signal: DefenderSignal, error: Optional[str] = None) -> None:
        async with self._cond:
            self._status = signal
            self._history.append(signal)
            if error is not None:
                self._error = error
            if self._on_emit is not None:
                self._on_emit(signal, error)
            self._cond.notify_all()

    async def wait(self, signal: DefenderSignal, timeout: Optional[float] = None) -> None:
        """Block until the lifecycle emits `signal`. Raise on a prior FAILED or on timeout."""
        loop = asyncio.get_event_loop()
        deadline = None if timeout is None else loop.time() + timeout
        async with self._cond:
            while signal not in self._history:
                if DefenderSignal.FAILED in self._history and signal != DefenderSignal.FAILED:
                    raise DefenderLifecycleError(
                        f"defender failed before reaching {signal.value}: {self._error or 'unknown error'}"
                    )
                remaining = None if deadline is None else deadline - loop.time()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError(f"timed out waiting for defender signal {signal.value}")
                try:
                    await asyncio.wait_for(self._cond.wait(), timeout=remaining)
                except asyncio.TimeoutError:
                    raise TimeoutError(f"timed out waiting for defender signal {signal.value}")


def signal_recorder(experiment):
    """on_emit callback that records each defender signal (status + timestamp) onto the experiment."""
    _ts_field = {
        DefenderSignal.SETUP_STARTED: "defender_setup_started_at",
        DefenderSignal.READY: "defender_ready_at",
        DefenderSignal.RUNNING: "defender_started_at",
        DefenderSignal.STOPPING: "defender_stopping_at",
        DefenderSignal.STOPPED: "defender_stopped_at",
    }

    def _on_emit(signal: DefenderSignal, error) -> None:
        experiment.defender_status = signal.value
        field = _ts_field.get(signal)
        if field is not None and getattr(experiment, field) is None:
            setattr(experiment, field, datetime.now(timezone.utc))

    return _on_emit
