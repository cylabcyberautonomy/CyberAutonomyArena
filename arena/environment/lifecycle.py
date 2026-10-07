"""EnvironmentLifecycle: the environment system's own status signals, distinct from ExperimentStatus."""
from __future__ import annotations

from enum import Enum
from typing import Callable, Optional


class EnvironmentCommand(str, Enum):
    """Arena -> environment. The arena sends these to drive each phase. ACTIVATE/DEACTIVATE bound the request-serving window."""
    PROVISION = "Provision"   # bring the network + VMs up
    CONFIGURE = "Configure"   # run setup on the hosts
    ACTIVATE = "Activate"     # open the request-serving window (defender may now mutate topology)
    DEACTIVATE = "Deactivate" # close the request-serving window (attack phase over)
    TEARDOWN = "Teardown"     # tear it all down (collect runs best-effort just before)


class EnvironmentSignal(str, Enum):
    """Environment -> arena. The plugin emits these and the arena records them."""
    DEPLOYING = "Deploying"       # provision started (VMs/network coming up)
    DEPLOYED = "Deployed"         # provision finished
    CONFIGURING = "Configuring"   # configure started (ansible on the hosts)
    CONFIGURED = "Configured"     # configure finished. Environment ready
    SERVING = "Serving"           # ack of ACTIVATE — the request-serving window is open
    IDLE = "Idle"                 # ack of DEACTIVATE — the window closed, idling until teardown
    TEARING_DOWN = "TearingDown"  # teardown started
    TORN_DOWN = "TornDown"        # teardown finished. Resources reclaimed
    FAILED = "Failed"             # a phase raised


class EnvironmentLifecycle:
    def __init__(self,
                 on_emit: Optional[Callable[[EnvironmentSignal, Optional[str]], None]] = None,
                 on_command: Optional[Callable[[EnvironmentCommand], None]] = None,
                 on_request: Optional[Callable[[dict], None]] = None):
        # on_emit persists each signal, on_command records each command, on_request records each mutation event.
        self._on_emit = on_emit
        self._on_command = on_command
        self._on_request = on_request
        self._history: list[EnvironmentSignal] = []
        self._commands: list[EnvironmentCommand] = []
        self._requests: list[dict] = []
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
    def requests(self) -> list[dict]:
        """The trace of defender->env mutation events serviced in the SERVING window (one entry per EnvActionRequest)."""
        return list(self._requests)

    @property
    def error(self) -> Optional[str]:
        return self._error

    def record_request(self, entry: dict) -> None:
        """Arena -> lifecycle: record one serviced env-mutation event (a small plain dict)."""
        self._requests.append(entry)
        if self._on_request is not None:
            self._on_request(entry)

    def send(self, command: EnvironmentCommand) -> None:
        """Arena -> environment: record the command that drives the next phase."""
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


def signal_recorder(experiment):
    """on_emit callback that records each environment signal onto the experiment (environment_status)."""
    def _on_emit(signal: EnvironmentSignal, error) -> None:
        experiment.environment_status = signal.value

    return _on_emit
