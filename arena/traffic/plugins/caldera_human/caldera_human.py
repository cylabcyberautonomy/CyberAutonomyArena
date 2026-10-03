"""CalderaHuman background-traffic plugin.

Deploys the ``caldera-human-traffic`` daemon (which vendors MITRE Caldera's standalone ``pyhuman``) onto
the victim hosts and runs a persona there, generating benign user activity during the attack window — no
Caldera server, no second C2.

Full parity with the defender: the ENVIRONMENT hands this plugin a ``TrafficEnvSpec`` (victim inventory)
and a scoped ``SetupAccess`` per victim (traffic key + bastion routing). ``setup()`` INSTALLS the generator
pre-rotation (fatal); ``run()`` spawns a runner subprocess that STARTS the generators, touches the
readiness marker (the arena gates the attacker on it), holds until SIGTERM, then stops the generators and
pulls their labeled activity log. The plugin never reads a management key or parses a topology — it reaches
victims via the injected access.

Config (``type: "caldera_human"``):
    persona:         name of a persona JSON bundled in the repo (default office_worker)
    persona_inline:  a full persona object; overrides `persona` when set (AI-authored)
    allow_browser:   permit browser workflows (needs Chromium baked into victim images)
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

from ....config import ExperimentManagerConfig
from ....experiment_log import log, output_root
from ....ui_schema import PluginUISchema
from ..base import TrafficPlugin
from . import ansible as bg_ansible


def _resolve_bgtraffic_dir(cfg: ExperimentManagerConfig) -> Path:
    d = getattr(cfg, "caldera_human_dir", None)
    if not d:
        raise RuntimeError(
            "traffic=caldera_human requested but cfg.caldera_human_dir is unset — point it at a "
            "checkout of the caldera-human-traffic repo in config.yaml."
        )
    return Path(d)


def _import_repo(cfg: ExperimentManagerConfig):
    """Make the repo's (stdlib-only) package importable and return its modules.
    Used for harness-side validation before we ship a persona to hosts."""
    bg = _resolve_bgtraffic_dir(cfg)
    if str(bg) not in sys.path:
        sys.path.insert(0, str(bg))
    from caldera_human_traffic import persona as persona_mod  # noqa: WPS433
    from caldera_human_traffic import workflows as workflows_mod  # noqa: WPS433
    return persona_mod, workflows_mod


def _traffic_out(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
    return output_root(experiment_name, cfg) / experiment_name / "traffic"


class CalderaHumanTraffic(TrafficPlugin, config_type="caldera_human"):
    type: str = "caldera_human"
    persona: str = "office_worker"
    persona_inline: Optional[dict[str, Any]] = None
    allow_browser: bool = False
    allow_gui: bool = False

    # External repo path (the caldera-human-traffic checkout), resolved via cfg.plugin_dir.
    code_dir_field = "caldera_human_dir"
    # The runner just needs to identify the experiment; access / ansible bin / log_dir are injected.
    REQUIRED_CONFIG_KEYS = frozenset({"experiment_name"})

    # -- ansible binary resolution (backend fallback kept inside the plugin, not in generic run_traffic) --
    def _ansible_bin(self, cfg: ExperimentManagerConfig) -> Path:
        """Resolve ansible-playbook: prefer the plugin repo's own venv, then PATH, then (last resort)
        MHBench's installed venv. The repo ships pyhuman to victims and has no venv of its own today, so
        PATH / the MHBench fallback is the usual source — but no backend *credential* or *topology* is read."""
        candidates = []
        d = getattr(cfg, "caldera_human_dir", None)
        if d:
            candidates.append(Path(d) / ".venv" / "bin" / "ansible-playbook")
        which = shutil.which("ansible-playbook")
        if which:
            candidates.append(Path(which))
        candidates.append(Path(cfg.mhbench_dir) / ".venv" / "bin" / "ansible-playbook")
        for c in candidates:
            if c and Path(c).exists():
                return c
        raise RuntimeError(
            "ansible-playbook not found for background traffic (checked the plugin venv, PATH, and the "
            "MHBench venv). Install ansible or set caldera_human_dir to a checkout with a .venv.")

    # -- persona resolution + validation (harness side) --------------------
    def _render_persona_file(self, cfg: ExperimentManagerConfig, dest_dir: Path) -> Path:
        """Resolve the persona (inline or bundled), validate it against the repo's schema + host
        runnability, and write it to a control-node file the install play copies to the victims."""
        persona_mod, workflows_mod = _import_repo(cfg)
        bg = _resolve_bgtraffic_dir(cfg)

        if self.persona_inline is not None:
            p = persona_mod.Persona.from_dict(self.persona_inline)
            data = self.persona_inline
        else:
            src = bg / "caldera_human_traffic" / "personas" / f"{self.persona}.json"
            if not src.exists():
                raise RuntimeError(f"bundled persona {self.persona!r} not found at {src}")
            p = persona_mod.Persona.load(src)
            data = json.loads(src.read_text())

        reasons = workflows_mod.check_persona_runnable(
            [a.workflow for a in p.activities], allow_browser=self.allow_browser, allow_gui=self.allow_gui
        )
        if reasons:
            raise RuntimeError(f"persona {p.name!r} not runnable on victim hosts: {'; '.join(reasons)}")

        dest_dir.mkdir(parents=True, exist_ok=True)
        out = dest_dir / "persona.json"
        out.write_text(json.dumps(data, indent=2))
        return out

    @staticmethod
    def _access_dicts(traffic_access) -> list[dict]:
        """Normalize the injected SetupAccess list (models or dicts) to plain dicts for the ansible helper."""
        out = []
        for a in (traffic_access or []):
            out.append(a if isinstance(a, dict) else a.model_dump())
        return out

    # -- lifecycle ---------------------------------------------------------
    async def setup(self, experiment, cfg: ExperimentManagerConfig,
                    traffic_env_spec=None, traffic_access=None, bastion_ip: Optional[str] = None) -> None:
        """INSTALL the generator + persona onto the victims (pre-rotation, fatal). Reaches each victim via
        the env-produced SetupAccess (scoped traffic key + bastion routing) — no management key, no topology."""
        bg = _resolve_bgtraffic_dir(cfg)
        out_dir = _traffic_out(experiment.experiment_name, cfg)
        persona_file = self._render_persona_file(cfg, out_dir)  # validates too
        access = self._access_dicts(traffic_access)
        if not access:
            raise RuntimeError("background traffic install: the environment produced no victim access "
                               "(empty traffic_setup_access)")
        ansible_bin = str(self._ansible_bin(cfg))
        log(experiment.experiment_name,
            f"[traffic] installing caldera_human (persona={self.persona_inline and '<inline>' or self.persona}) "
            f"on {len(access)} victim(s)")
        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: bg_ansible.run_play(
                action="install",
                access=access,
                ansible_playbook_bin=ansible_bin,
                extravars={
                    "bgtraffic_src": str(bg),
                    "bgtraffic_persona_src": str(persona_file),
                    "bgtraffic_allow_browser": self.allow_browser,
                    "bgtraffic_allow_gui": self.allow_gui,
                },
                log_path=out_dir / "bgtraffic_ansible.log",
            ),
        )

    def build_config(self, experiment_name: str, environment) -> dict:
        # traffic_setup_access (per-victim key + routing), log_dir, bastion_ip, management_ip are injected
        # by traffic.run_traffic(); ansible_playbook_bin is added by run() (it needs cfg). The runner reads
        # all of them plus these identity/profile fields.
        return {
            "type": self.type,
            "experiment_name": experiment_name,
            "persona": self.persona_inline and "<inline>" or self.persona,
            "allow_browser": self.allow_browser,
            "allow_gui": self.allow_gui,
        }

    async def run(self, config_path: Path, experiment_name: str,
                  cfg: ExperimentManagerConfig) -> asyncio.subprocess.Process:
        """Spawn the traffic runner (stdlib; manager interpreter). It STARTS the generators, touches the
        readiness marker, idles until SIGTERM, then stops the generators + pulls the activity log."""
        # Add the resolved ansible binary to the config (run_traffic wrote it; run() has cfg to resolve bin).
        data = json.loads(config_path.read_text())
        data["ansible_playbook_bin"] = str(self._ansible_bin(cfg))
        config_path.write_text(json.dumps(data, indent=2))

        out_dir = _traffic_out(experiment_name, cfg)
        out_dir.mkdir(parents=True, exist_ok=True)
        log_file = open(out_dir / "traffic.log", "a")
        return await asyncio.create_subprocess_exec(
            sys.executable,
            str(Path(__file__).parent / "runner.py"),
            str(config_path),
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

    # -- dashboard schema --------------------------------------------------
    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "caldera_human",
            "label": "Caldera Human (background traffic)",
            "cartesian_product": False,
            "fields": [
                {
                    "field_type": "text_with_suggestions",
                    "label": "Persona",
                    "key": "persona",
                    "suggestions": ["office_worker"],
                    "default": "office_worker",
                },
            ],
        }
