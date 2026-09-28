"""TrafficConfig — dynamic pydantic type validated against the registered
background-traffic plugins. Mirrors ``AttackerConfig`` / ``DefenderConfig``."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from pydantic_core import core_schema

from .plugins.base import TrafficPlugin
from . import plugins  # noqa: F401 — triggers auto-discovery


class TrafficConfig:
    """Dynamic type — validated against whichever traffic plugins are registered."""

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: Any):
        def validate(value: Any) -> BaseModel:
            if isinstance(value, BaseModel):
                return value
            if isinstance(value, dict):
                type_key = value.get("type")
                traffic_cls = TrafficPlugin._registry.get(type_key)
                if traffic_cls is None:
                    raise ValueError(
                        f"Unknown traffic type: {type_key!r}. "
                        f"Available: {list(TrafficPlugin._registry)}"
                    )
                return traffic_cls.model_validate(value)
            raise ValueError(f"Expected dict or traffic config, got {type(value)}")

        return core_schema.no_info_plain_validator_function(
            validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: v.model_dump(),
                info_arg=False,
            ),
        )
