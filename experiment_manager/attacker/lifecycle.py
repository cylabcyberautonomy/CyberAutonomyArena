"""AttackerLifecycle — the arena<->attacker handshake channel.

The arena drives the attacker through a fixed sequence, waiting for each signal before it sends
the next (a handshake at every step):

    arena: send start_setup ─► attacker: SETUP_STARTED ─► (setup runs) ─► attacker: READY
    arena: send start       ─► attacker: RUNNING
    arena: send stop        ─► attacker: STOPPING ─► attacker: STOPPED

Signals are recorded on the Experiment (`attacker_status` + timestamps) so an observer can see
exactly which phase the attacker is in, and a hang shows up as a stalled status with a distinct
timeout (e.g. stuck at SETUP_STARTED, never reaching READY) instead of a silent block.

This is an in-process channel: the arena and the attacker plugin run in the same event loop, so
`emit()` from the attacker side and `wait()` from the arena side are asyncio primitives. FAILED
short-circuits any pending wait with the underlying error.
"""
from __future__ import annotations

import asyncio
from enum import Enum
from typing import Callable, Optional


class AttackerSignal(str, Enum):
    SETUP_STARTED = "SetupStarted"
    READY = "Ready"
    RUNNING = "Running"
    STOPPING = "Stopping"
    STOPPED = "Stopped"
    FAILED = "Failed"


class AttackerLifecycleError(RuntimeError):
    """Raised from wait() when the attacker emitted FAILED before the awaited signal."""


class AttackerLifecycle:
    def __init__(self, on_emit: Optional[Callable[[AttackerSignal, Optional[str]], None]] = None):
        # on_emit lets the arena persist each signal (e.g. onto the Experiment record). Called
        # synchronously inside emit(), before waiters are woken.
        self._on_emit = on_emit
        self._history: list[AttackerSignal] = []
        self._status: Optional[AttackerSignal] = None
        self._error: Optional[str] = None
        self._cond = asyncio.Condition()

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
        """Block until `signal` has been emitted. Raises AttackerLifecycleError if the attacker
        emitted FAILED first, or TimeoutError if `timeout` elapses."""
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
