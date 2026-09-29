"""EnvironmentLifecycle — the environment system's own status signals.

The environment box emits its lifecycle as the arena drives it (see the design diagram):

    provision:  DEPLOYING   -> DEPLOYED
    configure:  CONFIGURING -> CONFIGURED
    teardown:   TEARING_DOWN -> TORN_DOWN
    any phase raising -> FAILED (with the error)

These are the environment's OWN signals, distinct from the whole-experiment ExperimentStatus.
The plugin emits them (so a new environment plugin gets the same signals); the arena supplies an
`on_emit` that persists the latest onto the Experiment (`environment_status`) so an observer can
see exactly which phase the environment is in, and a hang shows up as a stalled signal.

Emit-only + synchronous: unlike the attacker (a separate process the arena hands off to and waits
on), the environment is driven in-process and synchronously by the arena, so there is no
command/wait handshake — just recorded signals.
"""
from __future__ import annotations

from enum import Enum
from typing import Callable, Optional


class EnvironmentSignal(str, Enum):
    """Environment -> arena. The plugin EMITS these; the arena records them."""
    DEPLOYING = "Deploying"       # provision started (VMs/network coming up)
    DEPLOYED = "Deployed"         # provision finished
    CONFIGURING = "Configuring"   # configure started (ansible on the hosts)
    CONFIGURED = "Configured"     # configure finished; environment ready
    TEARING_DOWN = "TearingDown"  # teardown started
    TORN_DOWN = "TornDown"        # teardown finished; resources reclaimed
    FAILED = "Failed"             # a phase raised


class EnvironmentLifecycle:
    def __init__(self, on_emit: Optional[Callable[[EnvironmentSignal, Optional[str]], None]] = None):
        # on_emit persists each signal (e.g. onto the Experiment). Called synchronously.
        self._on_emit = on_emit
        self._history: list[EnvironmentSignal] = []
        self._status: Optional[EnvironmentSignal] = None
        self._error: Optional[str] = None

    @property
    def status(self) -> Optional[EnvironmentSignal]:
        return self._status

    @property
    def history(self) -> list[EnvironmentSignal]:
        return list(self._history)

    @property
    def error(self) -> Optional[str]:
        return self._error

    def emit(self, signal: EnvironmentSignal, error: Optional[str] = None) -> None:
        self._status = signal
        self._history.append(signal)
        if error is not None:
            self._error = error
        if self._on_emit is not None:
            self._on_emit(signal, error)
