"""CalderaHuman background-traffic plugin.

Deploys the ``caldera-human-traffic`` daemon (which vendors MITRE Caldera's
standalone ``pyhuman``) onto the victim hosts and runs a persona there, generating
benign user activity during the attack window — no Caldera server, no second C2.

Phase 1 (this plugin): an *offline* persona — either one bundled in the repo
(``persona="office_worker"``) or one authored inline (``persona_inline={...}``, e.g.
by an LLM) — is shipped to every victim and run statically. Phase 2 (control plane
in the repo) will let an author adjust it mid-run.

Config (``type: "caldera_human"``):
    persona:         name of a persona JSON bundled in the repo (default office_worker)
    persona_inline:  a full persona object; overrides `persona` when set (AI-authored)
    allow_browser:   permit browser workflows (needs Chromium baked into victim images)
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel

from ....config import ExperimentManagerConfig
from ....experiment_log import log, output_root
from ....ui_schema import PluginUISchema
from ..base import TrafficPlugin
from . import ansible as bg_ansible


def _resolve_bgtraffic_dir(cfg: ExperimentManagerConfig) -> Path:
    d = getattr(cfg, "bgtraffic_dir", None)
    if not d:
        raise RuntimeError(
            "traffic=caldera_human requested but cfg.bgtraffic_dir is unset — point it at a "
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


def _mhbench_ssh_key(cfg: ExperimentManagerConfig) -> Path:
    """Read ssh_key_path from MHBench's config (the key it injected into the hosts),
    falling back to the default all three MHBench configs use."""
    default = Path("~/.ssh/id_ed25519").expanduser()
    try:
        rel = getattr(cfg, "mhbench_config", None) or "config/config.yaml"
        data = yaml.safe_load((cfg.mhbench_dir / rel).read_text())
        backend = data.get("backend", "openstack")
        block = data.get(backend, {}) if isinstance(data.get(backend), dict) else {}
        key = block.get("ssh_key_path") or data.get("ssh_key_path")
        return Path(os.path.expanduser(key)) if key else default
    except Exception:  # noqa: BLE001 — config shape drift must not break traffic; use the default key
        return default


def _topology_path(cfg: ExperimentManagerConfig, environment_spec: str) -> Path:
    # environment_spec is a PATH to a topology JSON (absolute, or relative to mhbench_dir).
    p = Path(environment_spec)
    return p if p.is_absolute() else cfg.mhbench_dir / p


def _ansible_playbook_bin(cfg: ExperimentManagerConfig) -> Path:
    return cfg.mhbench_dir / ".venv" / "bin" / "ansible-playbook"


def _traffic_out(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
    return output_root(experiment_name, cfg) / experiment_name / "traffic"


class CalderaHumanTraffic(TrafficPlugin, config_type="caldera_human"):
    type: str = "caldera_human"
    persona: str = "office_worker"
    persona_inline: Optional[dict[str, Any]] = None
    allow_browser: bool = False
    allow_gui: bool = False

    # -- persona resolution + validation (harness side) --------------------
    def _render_persona_file(self, cfg: ExperimentManagerConfig, dest_dir: Path) -> Path:
        """Resolve the persona (inline or bundled), validate it against the repo's
        schema + host runnability, and write it to a control-node file the play copies."""
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
    def _recover_bastion_ip(experiment, cfg: ExperimentManagerConfig) -> Optional[str]:
        """Re-read the bastion floating IP from where provisioning wrote it — the
        teardown path (stop/collect) runs without the live bastion_ip, exactly like
        collect_environment/rotate_environment do."""
        pr = output_root(experiment.experiment_name, cfg) / experiment.experiment_name / "experiment" / "provision_result.json"
        if pr.exists():
            try:
                return json.loads(pr.read_text()).get("mgmt_ip")
            except Exception:  # noqa: BLE001
                return None
        return None

    def _common(self, experiment, cfg: ExperimentManagerConfig, bastion_ip: Optional[str]) -> dict:
        if bastion_ip is None:
            bastion_ip = self._recover_bastion_ip(experiment, cfg)
        if bastion_ip is None:
            raise RuntimeError("CalderaHumanTraffic needs the experiment bastion IP (bastion_ip).")
        return dict(
            topology_path=_topology_path(cfg, experiment.environment_spec),
            bastion_ip=bastion_ip,
            ssh_key=_mhbench_ssh_key(cfg),
            ansible_playbook_bin=_ansible_playbook_bin(cfg),
            log_path=_traffic_out(experiment.experiment_name, cfg) / "bgtraffic_ansible.log",
        )

    # -- lifecycle ---------------------------------------------------------
    async def setup(self, experiment, cfg: ExperimentManagerConfig, bastion_ip: Optional[str]) -> None:
        import asyncio

        bg = _resolve_bgtraffic_dir(cfg)
        out_dir = _traffic_out(experiment.experiment_name, cfg)
        persona_file = self._render_persona_file(cfg, out_dir)  # validates too
        common = self._common(experiment, cfg, bastion_ip)
        log(experiment.experiment_name,
            f"[traffic] installing caldera_human (persona={self.persona_inline and '<inline>' or self.persona}) on victims")
        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: bg_ansible.run_play(
                action="install",
                extravars={
                    "bgtraffic_src": str(bg),
                    "bgtraffic_persona_src": str(persona_file),
                    "bgtraffic_allow_browser": self.allow_browser,
                    "bgtraffic_allow_gui": self.allow_gui,
                },
                **common,
            ),
        )

    async def start(self, experiment, cfg: ExperimentManagerConfig, bastion_ip: Optional[str]) -> None:
        import asyncio

        common = self._common(experiment, cfg, bastion_ip)
        log(experiment.experiment_name, "[traffic] starting caldera_human daemon on victims")
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: bg_ansible.run_play(action="start", extravars={}, **common)
        )

    async def stop(self, experiment, cfg: ExperimentManagerConfig, bastion_ip: Optional[str]) -> None:
        import asyncio

        try:
            common = self._common(experiment, cfg, bastion_ip)
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: bg_ansible.run_play(action="stop", extravars={}, **common)
            )
        except Exception:  # noqa: BLE001 — stop is best-effort (host may already be gone)
            log(experiment.experiment_name, "[traffic] stop failed (best-effort) — continuing")

    async def collect_logs(self, experiment, cfg: ExperimentManagerConfig, dest: Path, bastion_ip: Optional[str]) -> None:
        import asyncio

        common = self._common(experiment, cfg, bastion_ip)
        collect_dir = dest / "traffic" / "activity_logs"
        collect_dir.mkdir(parents=True, exist_ok=True)
        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: bg_ansible.run_play(
                action="collect",
                extravars={"bgtraffic_collect_dest": str(collect_dir)},
                **common,
            ),
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
