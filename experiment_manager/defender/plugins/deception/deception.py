from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Literal, Optional

from pydantic import field_validator

from ....config import ExperimentManagerConfig
from ....experiment_log import output_root
from ....environment import DeployedEnvironment
from ....ui_schema import PluginUISchema
from ..base import DefenderPlugin


class DeceptionDefenderPlugin(DefenderPlugin, config_type="deception"):
    type: Literal["deception"]
    strategy: str  # e.g. "DoNothing", "StaticLayered", "ReactiveLayered"
    arsenal: dict[str, int] = {}

    @field_validator("strategy", mode="before")
    @classmethod
    def _normalize_strategy(cls, value):
        if isinstance(value, list):
            return value[0] if value else "DoNothing"
        return value

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "deception",
            "label": "Deception",
            "cartesian_product": False,
            "fields": [
                {
                    "field_type": "flat_checkboxes",
                    "label": "Strategy",
                    "key": "strategy",
                    "options": [
                        "DoNothing", "StaticLayered", "ReactiveLayered",
                        "ReactiveStandalone", "StaticStandalone",
                        "NaiveDecoyCredential", "NaiveDecoyHost",
                    ],
                    "short_names": {
                        "DoNothing": "donothing",
                        "StaticLayered": "static_lyr",
                        "ReactiveLayered": "react_lyr",
                        "ReactiveStandalone": "react_solo",
                        "StaticStandalone": "static_solo",
                        "NaiveDecoyCredential": "decoy_cred",
                        "NaiveDecoyHost": "decoy_host",
                    },
                },
                {
                    "field_type": "key_value_pairs",
                    "label": "Arsenal",
                    "key": "arsenal",
                    # Keys must match what each Strategy.initialize() actually reads from
                    # arsenal.storage (see defender/strategy/*.py in the deception repo) -
                    # they're capability/Action class names, not free-form labels. Every
                    # strategy but DoNothing needs at least one of these three:
                    # DeployDecoy + HoneyCredentials (Static*/Reactive*/NaiveDecoyCredential/
                    # NaiveDecoyHost), plus RestoreServer for ReactiveLayered/
                    # ReactiveStandalone specifically. A wrong/missing key here is a
                    # KeyError crash in Strategy.initialize(), not a silent no-op -
                    # confirmed live (StaticLayered crashed on a stale "honeypot" default
                    # that doesn't match anything any Strategy class actually looks up).
                    "entries": [
                        {"key": "DeployDecoy", "value": "2"},
                        {"key": "HoneyCredentials", "value": "2"},
                        {"key": "RestoreServer", "value": "2"},
                    ],
                    "key_short_names": {
                        "DeployDecoy": "decoy",
                        "HoneyCredentials": "honeycred",
                        "RestoreServer": "restore",
                    },
                },
            ],
        }

    def box_ingress(self) -> dict[str, list[int]]:
        # Reactive strategies read the box ES telemetry; static ones ignore it (harmless to route).
        return {"telemetry": [9200]}

    def build_config(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
    ) -> dict:
        return {
            "experiment_name": experiment_name,
            "strategy": self.strategy,
            "arsenal": self.arsenal,
            "topology_spec": environment.topology_spec if environment else None,
        }

    # No setup() override: ES is per-experiment on the defender box, stood up in run() via the base
    # prepare_box_es(). There is no shared Elasticsearch to bootstrap.

    async def teardown(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        cfg: ExperimentManagerConfig,
    ) -> None:
        # Kill the harness-host->box ES ssh -L tunnel. (Stray decoy VMs this plugin's strategies deploy
        # via DeployDecoy are reaped by the environment's own teardown, not here.)
        self._teardown_box_es_tunnel(experiment_name, cfg)

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        # Stand up the per-experiment ES on the defender box + tunnel to it (blocking SSH work, so off
        # the event loop); the runner then reads es_url from the config.
        await asyncio.get_event_loop().run_in_executor(
            None, self.prepare_box_es, config_path, experiment_name, cfg)
        log_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender.log"
        return await self._run_deception_script(
            Path(__file__).parent / "runner.py", config_path, cfg, log_path
        )
