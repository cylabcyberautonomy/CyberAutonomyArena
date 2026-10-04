from typing import Any

from pydantic import BaseModel
from pydantic_core import core_schema

from .plugins.base import DefenderPlugin
from . import plugins  # noqa: F401 — triggers auto-discovery


class DefenderConfig:
    """Dynamic type — validated against whichever plugins are registered."""

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type: Any, handler: Any):
        def validate(value: Any) -> BaseModel:
            if isinstance(value, BaseModel):
                return value
            if isinstance(value, dict):
                type_key = value.get("type")
                defender_cls = DefenderPlugin._registry.get(type_key)
                if defender_cls is None:
                    raise ValueError(
                        f"Unknown defender type: {type_key!r}. "
                        f"Available: {list(DefenderPlugin._registry)}"
                    )
                return defender_cls.model_validate(value)
            raise ValueError(f"Expected dict or defender config, got {type(value)}")

        return core_schema.no_info_plain_validator_function(
            validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda v: v.model_dump(),
                info_arg=False,
            ),
        )

# NOTE: there is no longer a separate run_defender() launch step. DefenderPlugin.run_setup() now fully
# brings the defender to READY — it arms (setup + provision_box + build_config + prepare), LAUNCHES the
# reactive loop, blocks on wait_until_ready, emits READY, and returns the running process — symmetric with
# the attacker's run_setup. The arena calls run_setup() and then only emits RUNNING. (A defender's readiness
# is the live loop being up, so the launch can't precede readiness the way the attacker's does.)
