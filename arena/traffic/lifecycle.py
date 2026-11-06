"""TrafficLifecycle — the arena<->traffic handshake channel, symmetric with defender/lifecycle.py."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional


class TrafficCommand(str, Enum):
    """Arena -> traffic commands that drive each phase."""
    START_SETUP = "StartSetup"
    START = "Start"
    STOP = "Stop"


class TrafficSignal(str, Enum):
    """Traffic -> arena signals, recorded on the Experiment."""
    SETUP_STARTED = "SetupStarted"
    READY = "Ready"
    RUNNING = "Running"
    STOPPING = "Stopping"
    STOPPED = "Stopped"
    FAILED = "Failed"


class TrafficLifecycleError(RuntimeError):
    """Raised from wait() when the traffic system emitted FAILED before the awaited signal."""


class TrafficLifecycle:
    """Symmetric with AttackerLifecycle/DefenderLifecycle."""

    def __init__(self, on_emit: Optional[Callable[["TrafficSignal", Optional[str]], None]] = None,
                 on_command: Optional[Callable[["TrafficCommand"], None]] = None):
        self._on_emit = on_emit
        self._on_command = on_command
        self._history: list[TrafficSignal] = []
        self._commands: list[TrafficCommand] = []
        self._status: Optional[TrafficSignal] = None
        self._error: Optional[str] = None
        self._cond = asyncio.Condition()

    @property
    def commands(self) -> list["TrafficCommand"]:
        return list(self._commands)

    @property
    def status(self) -> Optional[TrafficSignal]:
        return self._status

    @property
    def history(self) -> list[TrafficSignal]:
        return list(self._history)

    async def send(self, command: "TrafficCommand") -> None:
        """Arena -> traffic: record + announce a command that drives the next phase."""
        async with self._cond:
            self._commands.append(command)
            if self._on_command is not None:
                self._on_command(command)
            self._cond.notify_all()

    async def emit(self, signal: TrafficSignal, error: Optional[str] = None) -> None:
        async with self._cond:
            self._status = signal
            self._history.append(signal)
            if error is not None:
                self._error = error
            if self._on_emit is not None:
                self._on_emit(signal, error)
            self._cond.notify_all()

    async def wait(self, signal: TrafficSignal, timeout: Optional[float] = None) -> None:
        """Block until the lifecycle emits `signal`. Raise on a prior FAILED or on timeout."""
        loop = asyncio.get_event_loop()
        deadline = None if timeout is None else loop.time() + timeout
        async with self._cond:
            while signal not in self._history:
                if TrafficSignal.FAILED in self._history and signal != TrafficSignal.FAILED:
                    raise TrafficLifecycleError(
                        f"traffic failed before reaching {signal.value}: {self._error or 'unknown error'}"
                    )
                remaining = None if deadline is None else deadline - loop.time()
                if remaining is not None and remaining <= 0:
                    raise TimeoutError(f"timed out waiting for traffic signal {signal.value}")
                try:
                    await asyncio.wait_for(self._cond.wait(), timeout=remaining)
                except asyncio.TimeoutError:
                    raise TimeoutError(f"timed out waiting for traffic signal {signal.value}")


def signal_recorder(experiment):
    """on_emit callback that records each traffic signal (status + timestamp) onto the experiment."""
    _ts_field = {
        TrafficSignal.SETUP_STARTED: "traffic_setup_started_at",
        TrafficSignal.READY: "traffic_ready_at",
        TrafficSignal.RUNNING: "traffic_started_at",
        TrafficSignal.STOPPING: "traffic_stopping_at",
        TrafficSignal.STOPPED: "traffic_stopped_at",
    }

    def _on_emit(signal: TrafficSignal, error) -> None:
        experiment.traffic_status = signal.value
        field = _ts_field.get(signal)
        if field is not None and getattr(experiment, field) is None:
            setattr(experiment, field, datetime.now(timezone.utc))

    return _on_emit
