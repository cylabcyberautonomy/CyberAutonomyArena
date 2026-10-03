"""TrafficLifecycle — the arena<->traffic handshake channel, symmetric with defender/lifecycle.py.

Traffic is the third driven system; like the defender it runs as a runner subprocess the arena spawns,
so the ARENA emits these signals as it drives/detects each phase (the readiness decision is made INSIDE
the runner and signalled to the arena by the `traffic_ready` marker — see TrafficPlugin.wait_until_ready):

    arena: send start_setup ─► traffic: SETUP_STARTED ─► (setup: install the generator + persona on the
                                                          victims — heavy, pre-rotation so install noise
                                                          is rotated away)
    arena: send start       ─► traffic: RUNNING placeholder... (handled below)

The phase sequence mirrors the defender exactly: SETUP_STARTED (install begun) → READY (the generators
are up on the victims and producing benign activity; the arena gates the attacker on this, so the
attack-phase telemetry actually contains background noise) → RUNNING (ack of start) → STOPPING → STOPPED.
FAILED short-circuits any pending wait with the underlying error.

Traffic is OPTIONAL: the arena constructs and drives this only when an experiment has a traffic config,
exactly like the defender — a run without traffic never touches any of it.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional


class TrafficCommand(str, Enum):
    """Arena -> traffic. The arena SENDS these to drive each phase."""
    START_SETUP = "StartSetup"   # begin setup (install generator + persona on the victims)
    START = "Start"              # generators are up — benign activity is now flowing during the attack
    STOP = "Stop"                # stop the generators


class TrafficSignal(str, Enum):
    """Traffic -> arena. Emitted as the arena drives/detects each phase; recorded on the Experiment."""
    SETUP_STARTED = "SetupStarted"   # ack of START_SETUP — install has begun
    READY = "Ready"                  # generators up on the victims and producing activity
    RUNNING = "Running"              # ack of START — background traffic active during the attack
    STOPPING = "Stopping"           # ack of STOP
    STOPPED = "Stopped"             # stop complete (or the runner exited on its own)
    FAILED = "Failed"               # a phase raised (install crashed, generators timed out, runner died)


class TrafficLifecycleError(RuntimeError):
    """Raised from wait() when the traffic system emitted FAILED before the awaited signal."""


class TrafficLifecycle:
    """Symmetric with DefenderLifecycle. on_emit persists each signal onto the experiment; on_command
    records each arena command. Both are called synchronously (before waiters are woken)."""

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
        """Block until `signal` has been emitted. Raises TrafficLifecycleError if the traffic system
        emitted FAILED first, or TimeoutError if `timeout` elapses."""
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


def signal_persister(experiment):
    """on_emit callback that records each traffic signal onto the experiment (status + the matching
    timestamp), mirroring defender/lifecycle.py's signal_persister. Sync (no I/O) — the arena calls
    registry.update() at phase boundaries to persist to disk."""
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
