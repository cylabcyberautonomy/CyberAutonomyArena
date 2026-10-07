"""AttackerLifecycle — the arena<->attacker handshake channel."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional


class AttackerCommand(str, Enum):
    """Arena -> attacker commands that drive each phase."""
    START_SETUP = "StartSetup"
    START_RUN = "StartRun"
    STOP = "Stop"


class AttackerSignal(str, Enum):
    """Attacker -> arena signals the arena waits on / records."""
    SETUP_STARTED = "SetupStarted"
    READY = "Ready"
    RUNNING = "Running"
    STOPPING = "Stopping"
    STOPPED = "Stopped"
    FAILED = "Failed"


class AttackerLifecycleError(RuntimeError):
    """Raised from wait() when the attacker emitted FAILED before the awaited signal."""


class AttackerLifecycle:
    def __init__(self, on_emit: Optional[Callable[[AttackerSignal, Optional[str]], None]] = None,
                 on_command: Optional[Callable[["AttackerCommand"], None]] = None):
        self._on_emit = on_emit
        self._on_command = on_command
        self._history: list[AttackerSignal] = []
        self._commands: list[AttackerCommand] = []
        self._status: Optional[AttackerSignal] = None
        self._error: Optional[str] = None
        self._cond = asyncio.Condition()

    @property
    def commands(self) -> list["AttackerCommand"]:
        return list(self._commands)

    async def send(self, command: "AttackerCommand") -> None:
        """Arena -> attacker: record + announce a command that drives the next phase."""
        async with self._cond:
            self._commands.append(command)
            if self._on_command is not None:
                self._on_command(command)
            self._cond.notify_all()

    @property
    def status(self) -> Optional[AttackerSignal]:
        return self._status

    @property
    def history(self) -> list[AttackerSignal]:
        return list(self._history)

    async def emit(self, signal: AttackerSignal, error: Optional[str] = None) -> None:
        async with self._cond:
            self._status = signal
            self._history.append(signal)
            if error is not None:
                self._error = error
            if self._on_emit is not None:
                self._on_emit(signal, error)
            self._cond.notify_all()

    async def wait(self, signal: AttackerSignal, timeout: Optional[float] = None) -> None:
        """Block until the attacker emits `signal`. Raise AttackerLifecycleError if the attacker
        emits FAILED first. Raise TimeoutError if `timeout` elapses."""
        loop = asyncio.get_event_loop()
        deadline = None if timeout is None else loop.time() + timeout
        async with self._cond:
            while signal not in self._history:
                if AttackerSignal.FAILED in self._history and signal != AttackerSignal.FAILED:
                    raise AttackerLifecycleError(
                        f"attacker failed before reaching {signal.value}: {self._error or 'unknown error'}"
                    )
                remaining = None if deadline is None else deadline - loop.time()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError(f"timed out waiting for attacker signal {signal.value}")
                try:
                    await asyncio.wait_for(self._cond.wait(), timeout=remaining)
                except asyncio.TimeoutError:
                    raise TimeoutError(f"timed out waiting for attacker signal {signal.value}")


def signal_recorder(experiment):
    """on_emit callback that records each attacker signal onto the experiment."""
    _ts_field = {
        AttackerSignal.SETUP_STARTED: "attacker_setup_started_at",
        AttackerSignal.READY: "attacker_ready_at",
        AttackerSignal.RUNNING: "attacker_started_at",
        AttackerSignal.STOPPING: "attacker_stopping_at",
        AttackerSignal.STOPPED: "attacker_stopped_at",
    }

    def _on_emit(signal: AttackerSignal, error) -> None:
        experiment.attacker_status = signal.value
        field = _ts_field.get(signal)
        if field is not None and getattr(experiment, field) is None:
            setattr(experiment, field, datetime.now(timezone.utc))

    return _on_emit
