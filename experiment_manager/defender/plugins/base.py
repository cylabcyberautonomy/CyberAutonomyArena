import asyncio
import os
import subprocess
from abc import abstractmethod
from pathlib import Path
from typing import ClassVar, Optional

from pydantic import BaseModel

from ...config import ExperimentManagerConfig
from ...environment import DeployedEnvironment
from ...ui_schema import PluginUISchema


class DefenderPlugin(BaseModel):
    _registry: ClassVar[dict[str, type["DefenderPlugin"]]] = {}

    def __init_subclass__(cls, config_type: str = None, **kwargs):
        super().__init_subclass__(**kwargs)
        if config_type is not None:
            DefenderPlugin._registry[config_type] = cls

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        raise NotImplementedError(f"{cls.__name__} must implement ui_schema()")

    async def setup(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        cfg: ExperimentManagerConfig,
        mgmt_ip: Optional[str] = None,
    ) -> None:
        """One-time setup this defender needs before it can run (e.g. ensuring shared
        infrastructure like Elasticsearch is up, installing Falco on the experiment's
        hosts). Runs once, before build_config()/run() - default no-op. Mirrors
        AttackerPlugin.setup(); unlike that one there's no per-defender resource (a C2
        container) to tear down on failure, so this has no transactional cleanup -
        raising here just fails the defender start (see run_defender()'s caller).

        `mgmt_ip` is this experiment's own bastion floating IP (from MHBench
        provisioning) - NOT the same as cfg.host_ip (the harness's own fixed
        address, used for Elasticsearch). Any AnsibleRunner use needs THIS one to
        SSH-ProxyCommand into the experiment's internal hosts at all."""

    @abstractmethod
    def build_config(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
    ) -> dict: ...

    @abstractmethod
    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process: ...

    @staticmethod
    async def _run_deception_script(
        script_path: Path,
        config_path: Path,
        cfg: ExperimentManagerConfig,
        log_path: Path,
    ) -> asyncio.subprocess.Process:
        """Spawn a script (runner.py or setup.py) in deception_dir's own venv, with
        deception_dir on PYTHONPATH so its packages are importable. Shared by every
        DefenderPlugin subclass backed by that repo (deception/prompt_injection/
        llm_soc) - both their run() (the long-running defender loop) and setup()
        (one-time pre-run setup) need exactly this, just pointed at a different
        script. Does not wait for exit - callers await the process themselves if
        they need to (setup() does; run() hands the live process back to the
        harness)."""
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = open(log_path, "a")
        python = str(cfg.get_deception_python())
        pythonpath_parts = [str(cfg.deception_dir)]
        existing_pythonpath = os.environ.get("PYTHONPATH", "")
        if existing_pythonpath:
            pythonpath_parts.append(existing_pythonpath)
        pythonpath = os.pathsep.join(pythonpath_parts)
        return await asyncio.create_subprocess_exec(
            python,
            str(script_path),
            str(config_path),
            cwd=str(cfg.deception_dir),
            env={**os.environ, "PYTHONPATH": pythonpath},
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

    @classmethod
    async def _run_deception_setup_script(
        cls,
        script_dir: Path,
        setup_config: dict,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> None:
        """Write `setup_config` to defender/setup_config.json, run script_dir/setup.py
        against it in deception_dir's venv, and wait for it - unlike
        _run_deception_script, this one blocks until the setup script exits and
        raises if it failed, since build_config()/run() must not start until setup
        has actually finished."""
        import json
        from ...experiment_log import output_root

        defender_dir = output_root(experiment_name, cfg) / experiment_name / "defender"
        defender_dir.mkdir(parents=True, exist_ok=True)
        config_path = defender_dir / "setup_config.json"
        config_path.write_text(json.dumps(setup_config, indent=2))
        log_path = defender_dir / "setup.log"
        proc = await cls._run_deception_script(script_dir / "setup.py", config_path, cfg, log_path)
        returncode = await proc.wait()
        if returncode != 0:
            raise RuntimeError(f"{cls.__name__} setup failed (exit {returncode}) - see {log_path}")
