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


class EnvironmentCommand(str, Enum):
    """Arena -> environment. The arena SENDS these to drive each phase; recorded for an auditable
    command/ack trace. NOTE: there is deliberately NO 'start/run' command — unlike the attacker, the
    environment has no active run phase; once provisioned+configured it just idles as VMs in the
    background until torn down."""
    PROVISION = "Provision"   # bring the network + VMs up
    CONFIGURE = "Configure"   # run setup on the hosts
    TEARDOWN = "Teardown"     # tear it all down (collect runs best-effort just before)


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
    def __init__(self,
                 on_emit: Optional[Callable[[EnvironmentSignal, Optional[str]], None]] = None,
                 on_command: Optional[Callable[[EnvironmentCommand], None]] = None):
        # on_emit persists each env->arena signal; on_command records each arena->env command.
        # Both called synchronously (the environment is driven in-process by the arena).
        self._on_emit = on_emit
        self._on_command = on_command
        self._history: list[EnvironmentSignal] = []
        self._commands: list[EnvironmentCommand] = []
        self._status: Optional[EnvironmentSignal] = None
        self._error: Optional[str] = None

    @property
    def status(self) -> Optional[EnvironmentSignal]:
        return self._status

    @property
    def history(self) -> list[EnvironmentSignal]:
        return list(self._history)

    @property
    def commands(self) -> list[EnvironmentCommand]:
        return list(self._commands)

    @property
    def error(self) -> Optional[str]:
        return self._error

    def send(self, command: EnvironmentCommand) -> None:
        """Arena -> environment: record the command that drives the next phase (in-process the arena
        then invokes the matching plugin method)."""
        self._commands.append(command)
        if self._on_command is not None:
            self._on_command(command)

    def emit(self, signal: EnvironmentSignal, error: Optional[str] = None) -> None:
        self._status = signal
        self._history.append(signal)
        if error is not None:
            self._error = error
        if self._on_emit is not None:
            self._on_emit(signal, error)
