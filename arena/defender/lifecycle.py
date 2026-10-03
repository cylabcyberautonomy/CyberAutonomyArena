"""DefenderLifecycle — the arena<->defender handshake channel, symmetric with attacker/lifecycle.py.

The arena drives the defender through a fixed sequence and records each signal, so an observer sees
exactly which phase the defender is in (and a hang shows as a stalled status with a distinct timeout
instead of one opaque "failed to arm"):

    arena: send start_setup ─► defender: SETUP_STARTED ─► (setup: install ES on the box / deploy
                                                            sensors+agents / arm the detection loop)
                            ─► defender: READY  (armed — the detection loop is up and reading its
                                                 telemetry; the arena gates the attacker on this)
    arena: send start       ─► defender: RUNNING  (actively defending while the attack runs)
    arena: send stop        ─► defender: STOPPING ─► defender: STOPPED

Difference from the attacker (whose plugin runs in the arena's event loop and emits its own acks):
the defender's *arming* is decided INSIDE its runner subprocess, signalled to the arena by the
`defender_ready` marker file (see DefenderPlugin.wait_until_ready). So the ARENA emits these signals
as it drives/detects each phase — the channel is the same asyncio primitive, the emitter is the arena.

FAILED short-circuits any pending wait with the underlying error, exactly like the attacker.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional


class DefenderCommand(str, Enum):
    """Arena -> defender. The arena SENDS these to drive each phase."""
    START_SETUP = "StartSetup"   # begin setup (ES on the box, sensor/agent deploy, arm the loop)
    START = "Start"              # everything is ready — the defender is now actively defending
    STOP = "Stop"                # stop the defender


class DefenderSignal(str, Enum):
    """Defender -> arena. Emitted as the arena drives/detects each phase; recorded on the Experiment."""
    SETUP_STARTED = "SetupStarted"   # ack of START_SETUP — setup has begun
    READY = "Ready"                  # armed: the detection loop is up and reading telemetry
    RUNNING = "Running"              # ack of START — actively defending
    STOPPING = "Stopping"           # ack of STOP
    STOPPED = "Stopped"             # stop complete (or the defender exited on its own)
    FAILED = "Failed"               # a phase raised (setup crashed, arming timed out, process died)


class DefenderLifecycleError(RuntimeError):
    """Raised from wait() when the defender emitted FAILED before the awaited signal."""


class DefenderLifecycle:
    """Symmetric with AttackerLifecycle. on_emit persists each signal onto the experiment; on_command
    records each arena command. Both are called synchronously (before waiters are woken)."""

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
        """Block until `signal` has been emitted. Raises DefenderLifecycleError if the defender
        emitted FAILED first, or TimeoutError if `timeout` elapses."""
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
    """on_emit callback that records each defender signal onto the experiment (status + the matching
    timestamp), mirroring attacker/lifecycle.py's signal_recorder. Sync (no I/O) — the arena calls registry.update()
    at phase boundaries to persist to disk."""
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
