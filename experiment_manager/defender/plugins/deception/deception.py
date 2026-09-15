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

    async def setup(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        cfg: ExperimentManagerConfig,
        mgmt_ip: Optional[str] = None,
    ) -> None:
        """Ensure the shared Elasticsearch instance is up (see setup.py) - this
        defender doesn't need Falco (SimpleTelemetryAnalysis doesn't consume it),
        so mgmt_ip (the experiment's bastion IP) isn't needed here."""
        await self._run_deception_setup_script(
            Path(__file__).parent,
            {"deception_dir": str(cfg.deception_dir), "management_ip": cfg.host_ip},
            experiment_name,
            cfg,
        )

    async def teardown(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        cfg: ExperimentManagerConfig,
    ) -> None:
        # Every strategy this plugin runs (Static*/Reactive*/NaiveDecoy*/...) can
        # deploy decoy VMs via DeployDecoy - clean them up regardless of which
        # strategy was actually used (see DefenderPlugin._teardown_decoys).
        await self._teardown_decoys(experiment_name, cfg)

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        log_path = output_root(experiment_name, cfg) / experiment_name / "defender" / "defender.log"
        return await self._run_deception_script(
            Path(__file__).parent / "runner.py", config_path, cfg, log_path
        )
