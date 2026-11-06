"""Persona traffic: runs the persona-traffic daemon (vendored MITRE pyhuman, no server)
on each traffic host, with a persona chosen per host role from a traffic profile."""
from __future__ import annotations

import asyncio
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Literal, Optional, Union

import yaml

from ....config import ExperimentManagerConfig
from ....experiment_log import log, output_root
from ....ui_schema import PluginUISchema
from ..base import PreparedTraffic, TrafficPlugin
from . import ansible as bg_ansible

_PROFILES_DIR = Path(__file__).resolve().parent / "profiles"
_ASSIGNMENTS_FILE = "assignments.json"

# A persona reference: a bundled persona name (str) or an inline persona object (dict).
PersonaRef = Union[str, dict[str, Any]]


class PreparedPersonaTraffic(PreparedTraffic):
    """Which persona setup() started on which host."""
    assignments: dict[str, str] = {}


class PersonaTraffic(TrafficPlugin, config_type="persona_traffic"):
    """Benign user activity from per-role personas, with a labelled activity log per host for scoring."""

    type: Literal["persona_traffic"]
    # Persona for every host whose role the profile does not name.
    persona: str = "office_worker"
    # Role profile: a path (abs, or a name under profiles/) or an inline {"default": ref, "roles": {role: ref|null}}.
    # A null role gets no traffic.
    profile: Optional[Union[str, dict[str, Any]]] = None
    allow_browser: bool = False
    allow_gui: bool = False
    # Seconds to keep retrying a rearm while a rebuilt host boots.
    rearm_timeout_seconds: int = 300

    code_dir_field = "persona_traffic_dir"
    REQUIRED_CONFIG_KEYS = frozenset({"experiment_name", "assignments"})

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "persona_traffic",
            "label": "Persona traffic (background activity)",
            "cartesian_product": False,
            "fields": [
                {"field_type": "text_with_suggestions", "label": "Default persona", "key": "persona",
                 "suggestions": ["office_worker"], "default": "office_worker"},
                {"field_type": "text_with_suggestions", "label": "Role profile", "key": "profile",
                 "suggestions": sorted(p.stem for p in _PROFILES_DIR.glob("*.json")), "default": ""},
            ],
        }

    @classmethod
    def example_prepared(cls) -> "PreparedPersonaTraffic":
        return PreparedPersonaTraffic(assignments={"webserver0": "web_admin", "database0": "office_worker"})

    def build_config(self, experiment_name: str, env_spec, prepared: "PreparedTraffic") -> dict:
        return {
            "type": self.type,
            "experiment_name": experiment_name,
            "assignments": dict(getattr(prepared, "assignments", {}) or {}),
            "allow_browser": self.allow_browser,
            "allow_gui": self.allow_gui,
            "warmup_seconds": self.warmup_seconds,
        }

    # -- profile + persona resolution (harness side) ---------------------------

    def _load_profile(self) -> dict:
        if self.profile is None or self.profile == "":
            return {}
        if isinstance(self.profile, dict):
            return self.profile
        p = Path(self.profile).expanduser()
        if not p.is_absolute() and not p.exists():
            p = _PROFILES_DIR / (self.profile if p.suffix else f"{self.profile}.json")
        if not p.exists():
            raise RuntimeError(f"traffic profile {self.profile!r} not found (looked at {p})")
        data = yaml.safe_load(p.read_text()) or {}
        if not isinstance(data, dict):
            raise RuntimeError(f"traffic profile {p} must contain a mapping")
        return data

    def _persona_for_role(self, profile: dict, role: Optional[str]) -> Optional[PersonaRef]:
        """The persona ref for a role; None means this role gets no traffic."""
        roles = profile.get("roles") or {}
        if role is not None and role in roles:
            return roles[role]
        return profile.get("default", self.persona)

    def _import_repo(self, cfg: ExperimentManagerConfig):
        repo = self._code_dir(cfg)
        if str(repo) not in sys.path:
            sys.path.insert(0, str(repo))
        from persona_traffic import persona as persona_mod  # noqa: WPS433
        from persona_traffic import workflows as workflows_mod  # noqa: WPS433
        return persona_mod, workflows_mod

    def _render_persona(self, cfg: ExperimentManagerConfig, ref: PersonaRef, dest_dir: Path) -> tuple[str, Path]:
        """Validate a persona ref and write it to a control-node file. Return (persona name, file)."""
        persona_mod, workflows_mod = self._import_repo(cfg)
        if isinstance(ref, dict):
            data = ref
        else:
            src = self._code_dir(cfg) / "persona_traffic" / "personas" / f"{ref}.json"
            if not src.exists():
                raise RuntimeError(f"bundled persona {ref!r} not found at {src}")
            data = json.loads(src.read_text())
        p = persona_mod.Persona.from_dict(data)
        reasons = workflows_mod.check_persona_runnable(
            [a.workflow for a in p.activities], allow_browser=self.allow_browser, allow_gui=self.allow_gui)
        if reasons:
            raise RuntimeError(f"persona {p.name!r} not runnable on the traffic hosts: {'; '.join(reasons)}")
        dest_dir.mkdir(parents=True, exist_ok=True)
        out = dest_dir / f"{p.name}.json"
        out.write_text(json.dumps(data, indent=2))
        return p.name, out

    def _ansible_bin(self, cfg: ExperimentManagerConfig) -> str:
        """The plugin repo's own venv ansible-playbook, else the one on PATH."""
        own = self._code_dir(cfg) / ".venv" / "bin" / "ansible-playbook"
        if own.exists():
            return str(own)
        found = shutil.which("ansible-playbook")
        if found:
            return found
        raise RuntimeError("ansible-playbook not found (checked the persona_traffic_dir venv and PATH)")

    @staticmethod
    def _out_dir(experiment_name: str, cfg: ExperimentManagerConfig) -> Path:
        return output_root(experiment_name, cfg) / experiment_name / "traffic"

    def _load_assignments(self, experiment_name: str, cfg: ExperimentManagerConfig) -> dict[str, str]:
        try:
            return json.loads((self._out_dir(experiment_name, cfg) / _ASSIGNMENTS_FILE).read_text())
        except Exception:  # noqa: BLE001
            return {}

    async def _play(self, cfg, experiment_name: str, action: str, access: list, extravars: dict,
                    hostvars: Optional[dict] = None) -> None:
        await asyncio.to_thread(
            bg_ansible.run_play, action=action, access=[a.model_dump() for a in access],
            ansible_playbook_bin=self._ansible_bin(cfg), extravars=extravars, hostvars=hostvars,
            log_path=self._out_dir(experiment_name, cfg) / "bgtraffic_ansible.log")

    def _install_vars(self, cfg: ExperimentManagerConfig) -> dict:
        return {"bgtraffic_src": str(self._code_dir(cfg)),
                "bgtraffic_allow_browser": self.allow_browser,
                "bgtraffic_allow_gui": self.allow_gui}

    # -- lifecycle -------------------------------------------------------------

    async def setup(self, experiment, cfg: ExperimentManagerConfig,
                    bastion_ip: Optional[str] = None, access=None) -> "PreparedPersonaTraffic":
        """Install + start a persona on every covered host; return once each unit is verified active."""
        name = experiment.experiment_name
        if not access:
            raise RuntimeError("persona_traffic: the environment produced no traffic host access")
        env_spec = getattr(experiment, "_traffic_env_spec", None)
        roles = {h.name: h.role for h in (env_spec.hosts if env_spec else [])}
        profile = self._load_profile()
        persona_dir = self._out_dir(name, cfg) / "personas"

        assignments: dict[str, str] = {}
        hostvars: dict[str, dict] = {}
        rendered: dict[str, tuple[str, Path]] = {}
        for a in access:
            ref = self._persona_for_role(profile, roles.get(a.name))
            if ref is None:
                continue
            key = json.dumps(ref, sort_keys=True)
            if key not in rendered:
                rendered[key] = self._render_persona(cfg, ref, persona_dir)
            pname, pfile = rendered[key]
            assignments[a.name] = pname
            hostvars[a.name] = {"bgtraffic_persona_src": str(pfile)}
        if not assignments:
            raise RuntimeError("persona_traffic: the profile assigns no persona to any host")
        covered = [a for a in access if a.name in assignments]
        (self._out_dir(name, cfg) / _ASSIGNMENTS_FILE).write_text(json.dumps(assignments, indent=2))

        log(name, f"[traffic] persona_traffic: {assignments}")
        await self._play(cfg, name, "install", covered, self._install_vars(cfg), hostvars)
        await self._play(cfg, name, "start", covered, {})
        return PreparedPersonaTraffic(assignments=assignments)

    async def stop(self, experiment, cfg: ExperimentManagerConfig, access=None) -> None:
        assignments = self._load_assignments(experiment.experiment_name, cfg)
        covered = [a for a in (access or []) if a.name in assignments]
        if covered:
            await self._play(cfg, experiment.experiment_name, "stop", covered, {})

    async def collect_logs(self, experiment, cfg: ExperimentManagerConfig, dest: Path, access=None) -> None:
        assignments = self._load_assignments(experiment.experiment_name, cfg)
        covered = [a for a in (access or []) if a.name in assignments]
        if covered:
            out = Path(dest) / "activity_logs"
            out.mkdir(parents=True, exist_ok=True)
            await self._play(cfg, experiment.experiment_name, "collect", covered,
                             {"bgtraffic_collect_dest": str(out)})

    async def rearm(self, experiment, cfg: ExperimentManagerConfig, access) -> None:
        """Reinstall + restart this host's persona after a rebuild, retrying while the host boots."""
        name = experiment.experiment_name
        pname = self._load_assignments(name, cfg).get(access.name)
        if pname is None:
            return
        pfile = self._out_dir(name, cfg) / "personas" / f"{pname}.json"
        hostvars = {access.name: {"bgtraffic_persona_src": str(pfile)}}
        deadline = asyncio.get_event_loop().time() + self.rearm_timeout_seconds
        while True:
            try:
                await self._play(cfg, name, "install", [access], self._install_vars(cfg), hostvars)
                await self._play(cfg, name, "start", [access], {})
                log(name, f"[traffic] rearmed {access.name} ({pname}) after rebuild")
                return
            except RuntimeError:
                if asyncio.get_event_loop().time() >= deadline:
                    raise
                await asyncio.sleep(15)
