"""Persona traffic: benign background activity on each traffic host from a LIST of generators per host
(persona daemon, stdlib script runner, GHOSTS Lite, ...), chosen per host role from a traffic profile,
plus per-host extras. See generators.py for the kinds and the profile ref forms."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import sys
from pathlib import Path
from typing import Any, Literal, Optional, Union

import yaml

from ....config import ExperimentManagerConfig
from ....experiment_log import log, output_root
from ....ui_schema import PluginUISchema
from ..base import PreparedTraffic, TrafficPlugin
from . import ansible as bg_ansible
from .generators import GeneratorKind, RenderedGenerator, hostvars_for, normalize_ref, render_generator

_PROFILES_DIR = Path(__file__).resolve().parent / "profiles"
_ASSIGNMENTS_FILE = "assignments.json"
_DRIVER = Path(__file__).resolve().parent / "aux" / "computer_use_driver.py"
_DRIVER_CONFIG = "computer_use_driver.json"


class PreparedPersonaTraffic(PreparedTraffic):
    """Which generators setup() started on which host (host -> generator names), and each name's kind."""
    assignments: dict[str, list[str]] = {}
    kinds: dict[str, str] = {}


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, list) else [v]


class PersonaTraffic(TrafficPlugin, config_type="persona_traffic"):
    """Benign user activity from per-role generator lists, with a labelled activity log per generator for scoring."""

    type: Literal["persona_traffic"]
    # Persona for every host whose role the profile does not name (legacy single-persona default).
    persona: str = "office_worker"
    # Profile: a path (abs, or a name under profiles/) or an inline mapping:
    #   {"default": ref | [ref, ...],
    #    "roles":   {role: ref | [ref, ...] | null},      # null opts a role out
    #    "hosts":   {host: ref | [ref, ...]}}             # added on top of the host's role list
    # A ref is a bundled persona name, an inline persona object, or {"generator": kind, ...}.
    profile: Optional[Union[str, dict[str, Any]]] = None
    allow_browser: bool = False
    allow_gui: bool = False
    # The login the persona daemon runs as (a persona ref may override it with "user").
    persona_user: str = "ubuntu"
    # KEY=VALUE file the harness-side computer_use driver loads before creating its model client (e.g. a
    # .env holding ANTHROPIC_API_KEY). Unset: the arena process's own environment.
    computer_use_env_file: Optional[str] = None
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
        return PreparedPersonaTraffic(assignments={"webserver0": ["web_admin"], "database0": ["office_worker"]},
                                      kinds={"web_admin": "persona", "office_worker": "persona"})

    def build_config(self, experiment_name: str, env_spec, prepared: "PreparedTraffic") -> dict:
        return {
            "type": self.type,
            "experiment_name": experiment_name,
            "assignments": dict(getattr(prepared, "assignments", {}) or {}),
            "generator_kinds": dict(getattr(prepared, "kinds", {}) or {}),
            "known_generators": sorted(GeneratorKind.registry),
            "allow_browser": self.allow_browser,
            "allow_gui": self.allow_gui,
            "warmup_seconds": self.warmup_seconds,
        }

    # -- profile resolution (harness side) --------------------------------------

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

    def _refs_for_host(self, profile: dict, host: str, role: Optional[str]) -> list:
        """The generator refs for one host: its role's list (or the default), plus the host's own extras."""
        roles = profile.get("roles") or {}
        if role is not None and role in roles:
            base = roles[role]
        else:
            base = profile.get("default", self.persona)
        return _as_list(base) + _as_list((profile.get("hosts") or {}).get(host))

    def _resolve(self, cfg: ExperimentManagerConfig, profile: dict, env_spec, hosts: list[str],
                 dest: Path) -> dict[str, list[RenderedGenerator]]:
        """Render every host's generator list. Identical specs render once; names are unique per host."""
        roles = {h.name: h.role for h in (env_spec.hosts if env_spec else [])}
        cache: dict[str, RenderedGenerator] = {}
        per_host: dict[str, list[RenderedGenerator]] = {}
        for host in hosts:
            gens: list[RenderedGenerator] = []
            for ref in self._refs_for_host(profile, host, roles.get(host)):
                spec = normalize_ref(ref)
                key = json.dumps(spec, sort_keys=True)
                if key not in cache:
                    cache[key] = render_generator(self, cfg, spec, env_spec, dest)
                g = cache[key]
                if any(x.name == g.name for x in gens):
                    raise RuntimeError(f"persona_traffic: host {host!r} gets two generators named {g.name!r}; "
                                       f"give one a distinct 'name'")
                gens.append(g)
            if gens:
                per_host[host] = gens
        return per_host

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

    def _load_assignments(self, experiment_name: str, cfg: ExperimentManagerConfig) -> dict[str, list[RenderedGenerator]]:
        try:
            raw = json.loads((self._out_dir(experiment_name, cfg) / _ASSIGNMENTS_FILE).read_text())
            return {h: [RenderedGenerator.from_dict(d) for d in gens] for h, gens in raw.items()}
        except Exception:  # noqa: BLE001
            return {}

    async def _play(self, cfg, experiment_name: str, action: str, access: list, extravars: dict,
                    hostvars: Optional[dict] = None) -> None:
        await asyncio.to_thread(
            bg_ansible.run_play, action=action, access=[a.model_dump() for a in access],
            ansible_playbook_bin=self._ansible_bin(cfg), extravars=extravars, hostvars=hostvars,
            log_path=self._out_dir(experiment_name, cfg) / "bgtraffic_ansible.log")

    # -- lifecycle -------------------------------------------------------------

    async def setup(self, experiment, cfg: ExperimentManagerConfig,
                    bastion_ip: Optional[str] = None, access=None) -> "PreparedPersonaTraffic":
        """Install + start every host's generators; return once each unit is verified active."""
        name = experiment.experiment_name
        if not access:
            raise RuntimeError("persona_traffic: the environment produced no traffic host access")
        env_spec = getattr(experiment, "_traffic_env_spec", None)
        profile = self._load_profile()
        per_host = self._resolve(cfg, profile, env_spec, [a.name for a in access],
                                 self._out_dir(name, cfg) / "generators")
        if not per_host:
            raise RuntimeError("persona_traffic: the profile assigns no generator to any host")
        (self._out_dir(name, cfg) / _ASSIGNMENTS_FILE).write_text(
            json.dumps({h: [g.to_dict() for g in gens] for h, gens in per_host.items()}, indent=2))
        host_side = self._host_side(per_host)
        covered = [a for a in access if a.name in host_side]
        hostvars = {h: hostvars_for(gens) for h, gens in host_side.items()}
        assignments = {h: [g.name for g in gens] for h, gens in per_host.items()}
        kinds = {g.name: g.kind for gens in per_host.values() for g in gens}

        log(name, f"[traffic] persona_traffic: {assignments}")
        if covered:
            await self._play(cfg, name, "install", covered, {}, hostvars)
            await self._play(cfg, name, "start", covered, {}, hostvars)
        return PreparedPersonaTraffic(assignments=assignments, kinds=kinds)

    # -- harness-side generators (computer_use): one driver process for every such host -------------

    async def start(self, prepared, config_path: Path, experiment_name: str, cfg: ExperimentManagerConfig,
                    access=None) -> Optional[asyncio.subprocess.Process]:
        """Launch the computer-use driver if any host has a harness-side generator; else nothing to run."""
        per_host = self._load_assignments(experiment_name, cfg)
        by_access = {a.name: a for a in (access or [])}
        hosts = []
        for h, gens in per_host.items():
            specs = [g.files["spec.json"] for g in gens if g.side == "harness"]
            if specs and h in by_access:
                hosts.append({**by_access[h].model_dump(), "generators": specs})
        if not hosts:
            return None
        out = self._out_dir(experiment_name, cfg)
        driver_cfg = out / _DRIVER_CONFIG
        driver_cfg.write_text(json.dumps({
            "experiment_name": experiment_name, "log_dir": str(out / "harness_activity"),
            "env_file": self.computer_use_env_file, "hosts": hosts}, indent=2))
        log_file = open(out / "computer_use_driver.log", "ab")
        process = await asyncio.create_subprocess_exec(
            sys.executable, str(_DRIVER), "--config", str(driver_cfg),
            stdout=log_file, stderr=asyncio.subprocess.STDOUT)
        log(experiment_name, f"[traffic] computer_use driver started (pid={process.pid}) for {[h['name'] for h in hosts]}")
        return process

    def _stop_driver(self, experiment) -> None:
        pid = getattr(experiment, "traffic_pid", None)
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    @staticmethod
    def _host_side(per_host: dict[str, list[RenderedGenerator]]) -> dict[str, list[RenderedGenerator]]:
        return {h: gs for h, gs in per_host.items() if any(g.side == "host" for g in gs)}

    def _covered(self, experiment, cfg, access) -> tuple[list, dict]:
        per_host = self._host_side(self._load_assignments(experiment.experiment_name, cfg))
        covered = [a for a in (access or []) if a.name in per_host]
        return covered, {a.name: hostvars_for(per_host[a.name]) for a in covered}

    async def stop(self, experiment, cfg: ExperimentManagerConfig, access=None) -> None:
        self._stop_driver(experiment)
        covered, hostvars = self._covered(experiment, cfg, access)
        if covered:
            await self._play(cfg, experiment.experiment_name, "stop", covered, {}, hostvars)

    async def collect_logs(self, experiment, cfg: ExperimentManagerConfig, dest: Path, access=None) -> None:
        out = Path(dest) / "activity_logs"
        covered, hostvars = self._covered(experiment, cfg, access)
        if covered:
            out.mkdir(parents=True, exist_ok=True)
            await self._play(cfg, experiment.experiment_name, "collect", covered,
                             {"bgtraffic_collect_dest": str(out)}, hostvars)
        harness = self._out_dir(experiment.experiment_name, cfg) / "harness_activity"
        if harness.is_dir():
            (out / "harness").mkdir(parents=True, exist_ok=True)
            for f in harness.glob("*.jsonl"):
                shutil.copy2(f, out / "harness" / f.name)

    async def rearm(self, experiment, cfg: ExperimentManagerConfig, access) -> None:
        """Reinstall + restart this host's generators after a rebuild, retrying while the host boots."""
        name = experiment.experiment_name
        gens = [g for g in self._load_assignments(name, cfg).get(access.name, []) if g.side == "host"]
        if not gens:
            return
        hostvars = {access.name: hostvars_for(gens)}
        deadline = asyncio.get_event_loop().time() + self.rearm_timeout_seconds
        while True:
            try:
                await self._play(cfg, name, "install", [access], {}, hostvars)
                await self._play(cfg, name, "start", [access], {}, hostvars)
                log(name, f"[traffic] rearmed {access.name} ({[g.name for g in gens]}) after rebuild")
                return
            except RuntimeError:
                if asyncio.get_event_loop().time() >= deadline:
                    raise
                await asyncio.sleep(15)
