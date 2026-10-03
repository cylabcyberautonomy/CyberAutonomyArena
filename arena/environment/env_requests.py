"""Environment-mutation EVENTS a running defender sends to the arena's environment service.

This is the dynamic counterpart to the one-shot, declarative env call that already exists today
(`DefenderPlugin.box_ingress()` -> `EnvironmentPlugin.program_ingress()`): instead of declaring its
needs up front at arm time, a *running* defender asks the environment to change the topology mid-run —
add a decoy host, rebuild a compromised one, remove one.

Why mediate through the environment at all (rather than the defender calling the cloud itself, which is
what the Perry actuators do today via `openstack.connect()`):

  * no god key — only the environment holds the management/cloud credential; the defender holds its
    own scoped key and an HTTP endpoint. A host the env creates for the defender comes back with a
    DEFENDER-SCOPED SetupAccess, nothing broader (see docs/security-model.md).
  * backend neutrality — the defender names WHAT it wants (a host, a rule); the env decides HOW its
    backend (OpenStack / GCP) makes it. The same event works on both.
  * admission — VMs the defender may add are pre-reserved at admission from `defender_vm_budget()`;
    the arena enforces that ceiling before it dispatches an AddHost, so a mid-run add can never
    oversubscribe the cluster (the room is already held).

The flow: the defender's RemoteEnvOrchestrator (Defense repo) serialises each capability/action into
one EnvActionRequest and POSTs it to the arena; the arena validates + accounts + dispatches to
`EnvironmentPlugin.handle_env_request`; the plugin actuates and returns an EnvActionResult.

Provider-agnostic DTOs: the env layer produces/consumes them; the SetupAccess carried back is the same
shared type the attacker/defender setup already uses (attacker/env_spec.py).
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel

from ..attacker.env_spec import SetupAccess  # the shared setup-access DTO (no arena import cycle)


class EnvActionKind(str, Enum):
    """The environment primitives a defender may request. Deliberately a small, bounded vocabulary of
    infra primitives — NOT an open "run arbitrary cloud ops" surface. It maps onto the Perry actuators
    that today hold `openstack_conn`: DeployDecoy -> ADD_HOST, RestoreServer -> REBUILD_HOST,
    ShutdownServer -> REMOVE_HOST. The ansible-over-bastion actuators (block_ip, AddFakeData,
    AddHoneyCredentials, StartHoneyService) need no cloud credential and stay defender-side, so they
    are intentionally absent here. (SET_NETWORK_RULE / ADD_SUBNET are reserved for later — backend-
    neutral SG blocking + honeynet segments — but are not part of the first cut.)"""
    ADD_HOST = "AddHost"
    REMOVE_HOST = "RemoveHost"
    REBUILD_HOST = "RebuildHost"


class EnvActionRequest(BaseModel):
    """One environment-mutation event. A flat shape keyed by `kind` (not a discriminated union) so the
    Defense-repo orchestrator can emit it without importing pydantic models — it builds a plain dict and
    the arena validates it here."""
    kind: EnvActionKind

    # ADD_HOST --------------------------------------------------------------
    name: Optional[str] = None     # requested host name (the env may sanitise/namespace it to avoid collisions)
    role: Optional[str] = None     # logical role / image hint (e.g. "decoy", "apache_vuln"); the env maps it to a backend image
    subnet: Optional[str] = None   # env subnet (by name) to place the host on; None -> the env's default victim subnet

    # REMOVE_HOST / REBUILD_HOST -------------------------------------------
    target: Optional[str] = None   # the existing host (name or ip) to act on


class EnvActionResult(BaseModel):
    """The environment's reply to one EnvActionRequest.

    For ADD_HOST: `name`/`ip` identify the new VM and `access` is a DEFENDER-SCOPED SetupAccess (key +
    routing) so the defender runs its OWN setup over it — sensor install, vulnerability, registration.
    This is the no-god-key split made concrete: the env PROVISIONS (holds the cloud cred), the defender
    CONFIGURES (holds only its scoped key). For REMOVE_HOST / REBUILD_HOST: only ok/error matter."""
    kind: EnvActionKind
    ok: bool = True
    name: Optional[str] = None
    ip: Optional[str] = None
    access: Optional[SetupAccess] = None
    error: Optional[str] = None


class EnvRequestUnsupported(RuntimeError):
    """Raised by an env plugin/backend that cannot satisfy a requested primitive — e.g. a static
    (non-instrumented) topology, or a GCP backend with no PE image for an `apache_vuln` decoy. The
    arena turns this into EnvActionResult(ok=False, error=...) rather than crashing the run, so a
    defender that over-asks degrades gracefully instead of failing the experiment."""
