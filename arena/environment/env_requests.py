"""Environment-mutation events a running defender sends to the arena's environment service."""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel

from ..defender.env_spec import DefenderSetupAccess  # defender-scoped setup access (ADD_HOST result)


class EnvActionKind(str, Enum):
    """The small, bounded set of environment primitives a defender may request."""
    ADD_HOST = "AddHost"
    REMOVE_HOST = "RemoveHost"
    REBUILD_HOST = "RebuildHost"


class EnvActionRequest(BaseModel):
    """One environment-mutation event, a flat shape keyed by `kind` so the orchestrator can emit a plain dict."""
    kind: EnvActionKind

    # ADD_HOST --------------------------------------------------------------
    name: Optional[str] = None     # requested host name (the env may sanitise or namespace it)
    role: Optional[str] = None     # role / image hint (e.g. "decoy", "apache_vuln"). The env maps it to an image
    subnet: Optional[str] = None   # env subnet (by name) to place the host on. None -> the default victim subnet

    # REMOVE_HOST / REBUILD_HOST -------------------------------------------
    target: Optional[str] = None   # the existing host (name or ip) to act on


class EnvActionResult(BaseModel):
    """The environment's reply to one EnvActionRequest.

    For ADD_HOST, `name`/`ip` identify the new VM and `access` is a defender-scoped DefenderSetupAccess so
    the defender runs its own setup over it. For REMOVE_HOST / REBUILD_HOST, only ok/error matter."""
    kind: EnvActionKind
    ok: bool = True
    name: Optional[str] = None
    ip: Optional[str] = None
    access: Optional[DefenderSetupAccess] = None
    error: Optional[str] = None


class EnvRequestUnsupported(RuntimeError):
    """Raised by an env plugin/backend that cannot satisfy a requested primitive, so the arena degrades gracefully."""
