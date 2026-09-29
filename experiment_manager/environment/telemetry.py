"""Telemetry-relay DTOs — the generic contract every environment plugin implements so the arena can
wire telemetry the SAME way regardless of backend (MHBench, Ludus, ...).

The model (see WHAT_TO_REFACTOR_ENVIRONMENT.md): sensors bake to ONE fixed ingest target (the relay,
on the environment's management host), and the relay REDIRECTS each stream to the consumer's endpoint.
No message bus, no per-sensor publishers.

  TelemetryIngest — the fixed bake target the environment guarantees: {host, port, scheme}. Constant
                    across runs for a given backend, so it can be baked into the sensor images.

  TelemetryRoute  — one forward rule the arena hands the relay: a consumer's telemetry requirement.
                    source_channel = which sensor stream (a relay port / logical name);
                    dest           = where to deliver it (host:port / URL);
                    protocol       = how (tcp / http / syslog / es-bulk / ...).
                    Grouping many routes by source_channel yields multi-stream routing AND same-stream
                    fan-out (one source, several dests) — both fall out of the list.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel


class TelemetryIngest(BaseModel):
    """The fixed bake target sensors ship to (the relay's ingest endpoint)."""
    host: str                       # constant per backend (e.g. the mgmt host's internal IP)
    port: int
    scheme: Literal["tcp", "http", "syslog"] = "tcp"


class TelemetryRoute(BaseModel):
    """One forward rule: deliver a source stream to a consumer's endpoint."""
    source_channel: str             # which sensor stream (relay port / logical name)
    dest: str                       # where to deliver (host:port or URL)
    protocol: Literal["tcp", "http", "syslog", "es-bulk"] = "tcp"
