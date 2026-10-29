"""Generator kinds a traffic profile can mix on one host.

A host's traffic is a LIST of generators, each running as its own systemd unit with its own labelled
activity log. A kind validates its spec on the harness, renders the files the host needs, and describes
its unit; the play (aux/bgtraffic.yml) is generic over kinds and never branches on one. Host-side code
must be stdlib-only (victim images have no pip mirror).

Kinds shipped here:
- ``persona``      the persona-traffic daemon (vendored MITRE pyhuman) from ``persona_traffic_dir``.
- ``script``       the plugin's own stdlib runner (aux/script_runner.py): weighted command groups fired as
                   a Poisson process, optionally entered through an SSH login on the host itself so the
                   process ancestry is sshd -> bash -> command, like a human's.
- ``ghosts_lite``  CMU SEI GHOSTS Lite driven by a timeline (ported from MHBench's
                   install_ghosts_lite_nostart.yml); the binary is fetched at install.
- ``computer_use`` a Claude computer-use agent driving the host's desktop (an mhbench
                   ``workstation_instrumented`` host: XFCE on a virtual display) through SSH + xdotool. It
                   runs HARNESS-SIDE (aux/computer_use_driver.py, launched by the plugin's start()), so the
                   model credential never reaches a victim; nothing is installed on the host for it.

A profile ref is one of: a bundled persona name (str), an inline persona (dict without ``generator``), or
``{"generator": "<kind>", ...}``. The first two are the legacy single-persona form and map to ``persona``.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Optional

_AUX = Path(__file__).resolve().parent / "aux"
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

# Host-side layout. One directory + one log per generator, so kinds never collide on a host.
HOST_DIR = "/opt/bgtraffic"
HOST_LOG_DIR = "/var/log/bgtraffic"
HOST_SSH_KEY = "/etc/bgtraffic/runner_key"   # host-local key the script runner makes for itself to log into local users

DEFAULT_GHOSTS_LITE_URL = "https://github.com/cmu-sei/GHOSTS/releases/latest/download/ghosts-lite.linux-x64.zip"

_TOKEN_RE = re.compile(r"^\{\{(hosts|ips|count):([A-Za-z0-9_-]+)\}\}$")


@dataclass
class RenderedGenerator:
    """One generator instance, fully resolved: what to ship to the host and how its unit runs.

    ``files``/``payloads`` are control-node sources; ``dir``/``log`` are host-side paths."""
    kind: str
    name: str
    user: str                         # the unit's User=
    exec_start: str                   # absolute command line; {dir}/{log} already substituted
    check_cmd: Optional[str] = None   # install-time preflight, run in dir; None = no preflight
    files: dict[str, str] = field(default_factory=dict)      # host path relative to dir -> control-node file
    payloads: list[str] = field(default_factory=list)        # control-node files/dirs copied INTO dir
    archive_url: Optional[str] = None                        # fetched + unpacked into dir at install
    log: Optional[str] = None         # host-side activity log to collect; None -> the unit's journal
    ssh_users: list[str] = field(default_factory=list)       # local users the runner logs into via sshd
    side: str = "host"                # "host": a unit on the victim; "harness": driven from the arena host

    @property
    def dir(self) -> str:
        return f"{HOST_DIR}/{self.name}"

    @property
    def unit(self) -> str:
        return f"bgtraffic-{self.name}.service"

    @property
    def log_path(self) -> str:
        return self.log or f"{HOST_LOG_DIR}/{self.name}.journal.jsonl"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "RenderedGenerator":
        return cls(**d)


def normalize_ref(ref: Any) -> dict:
    """A profile ref -> a generator spec dict with a ``generator`` key."""
    if isinstance(ref, str):
        return {"generator": "persona", "persona": ref}
    if isinstance(ref, dict):
        if "generator" in ref:
            return ref
        return {"generator": "persona", "persona": ref}
    raise RuntimeError(f"traffic profile ref must be a persona name, a persona object or a "
                       f"{{'generator': ...}} spec, got {type(ref).__name__}")


def _check_name(name: Any, what: str) -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise RuntimeError(f"{what}: name {name!r} must match {_NAME_RE.pattern}")
    return name


def _spec_dir(dest: Path, kind: str, name: str, spec: dict) -> Path:
    digest = hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()[:8]
    d = dest / f"{kind}-{name}-{digest}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _hosts_by_role(env_spec, role: str) -> list:
    return [h for h in (env_spec.hosts if env_spec else []) if h.role == role]


def expand_tokens(value: Any, env_spec) -> Any:
    """Resolve ``{{hosts:<role>}}`` / ``{{ips:<role>}}`` / ``{{count:<role>}}`` against the run's inventory.

    A string that is exactly one token becomes the list (or count); other values pass through, and
    containers are walked. Profiles use this to target peers without knowing the topology's size."""
    if isinstance(value, str):
        m = _TOKEN_RE.match(value.strip())
        if not m:
            return value
        what, role = m.groups()
        hosts = _hosts_by_role(env_spec, role)
        if what == "count":
            return len(hosts)
        if what == "ips":
            return [h.ip for h in hosts if h.ip]
        return [h.name for h in hosts]
    if isinstance(value, list):
        return [expand_tokens(v, env_spec) for v in value]
    if isinstance(value, dict):
        return {k: expand_tokens(v, env_spec) for k, v in value.items()}
    return value


class GeneratorKind:
    """A generator kind. Subclasses register under ``kind`` on definition."""
    kind: ClassVar[str] = ""
    registry: ClassVar[dict[str, "GeneratorKind"]] = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.kind:
            GeneratorKind.registry[cls.kind] = cls()

    def render(self, plugin, cfg, spec: dict, env_spec, dest: Path) -> RenderedGenerator:
        raise NotImplementedError


def render_generator(plugin, cfg, spec: dict, env_spec, dest: Path) -> RenderedGenerator:
    """Validate a normalized spec and render it. Raises RuntimeError with a precise message."""
    kind = spec.get("generator")
    gk = GeneratorKind.registry.get(kind)
    if gk is None:
        raise RuntimeError(f"unknown traffic generator {kind!r}; known: {sorted(GeneratorKind.registry)}")
    return gk.render(plugin, cfg, spec, env_spec, dest)


# -- persona: the pyhuman daemon ------------------------------------------------------------------

class PersonaKind(GeneratorKind):
    kind = "persona"

    @staticmethod
    def _import_repo(repo: Path):
        if str(repo) not in sys.path:
            sys.path.insert(0, str(repo))
        from persona_traffic import persona as persona_mod  # noqa: WPS433
        from persona_traffic import workflows as workflows_mod  # noqa: WPS433
        return persona_mod, workflows_mod

    def render(self, plugin, cfg, spec: dict, env_spec, dest: Path) -> RenderedGenerator:
        repo = plugin._code_dir(cfg)
        ref = spec.get("persona")
        if isinstance(ref, dict):
            data = ref
        elif isinstance(ref, str):
            src = repo / "persona_traffic" / "personas" / f"{ref}.json"
            if not src.exists():
                raise RuntimeError(f"bundled persona {ref!r} not found at {src}")
            data = json.loads(src.read_text())
        else:
            raise RuntimeError("persona generator needs 'persona': a bundled name or a persona object")
        persona_mod, workflows_mod = self._import_repo(repo)
        p = persona_mod.Persona.from_dict(data)
        reasons = workflows_mod.check_persona_runnable(
            [a.workflow for a in p.activities], allow_browser=plugin.allow_browser, allow_gui=plugin.allow_gui)
        if reasons:
            raise RuntimeError(f"persona {p.name!r} not runnable on the traffic hosts: {'; '.join(reasons)}")
        name = _check_name(spec.get("name", p.name), "persona generator")
        d = _spec_dir(dest, self.kind, name, spec)
        out = d / "persona.json"
        out.write_text(json.dumps(data, indent=2))
        flags = ("--allow-browser " if plugin.allow_browser else "") + ("--allow-gui " if plugin.allow_gui else "")
        g = RenderedGenerator(kind=self.kind, name=name, user=spec.get("user", plugin.persona_user), exec_start="")
        g.files = {"persona.json": str(out)}
        g.payloads = [str(repo / "persona_traffic"), str(repo / "vendor")]
        g.log = f"{HOST_LOG_DIR}/{name}.jsonl"
        g.exec_start = (f"/usr/bin/python3 -m persona_traffic.daemon --persona {g.dir}/persona.json "
                        f"--log {g.log} {flags}").strip()
        g.check_cmd = f"/usr/bin/python3 -m persona_traffic.daemon --persona {g.dir}/persona.json --check {flags}".strip()
        return g


# -- script: the plugin's own stdlib runner ---------------------------------------------------------

SCRIPT_ENTRIES = ("direct", "ssh")


def validate_script_spec(spec: dict) -> dict:
    """Shape-check a script spec (shared with the host-side runner's --check). Returns the spec."""
    problems: list[str] = []
    name = spec.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        problems.append(f"name {name!r} must match {_NAME_RE.pattern}")
    if spec.get("entry", "direct") not in SCRIPT_ENTRIES:
        problems.append(f"entry must be one of {SCRIPT_ENTRIES}")
    if not isinstance(spec.get("user", "ubuntu"), str):
        problems.append("user must be a string")
    rate = spec.get("events_per_hour")
    if not isinstance(rate, (int, float)) or isinstance(rate, bool) or rate <= 0:
        problems.append("events_per_hour must be a number > 0")
    for key in ("think_seconds", "command_timeout"):
        v = spec.get(key)
        if v is not None and (not isinstance(v, (int, float)) or isinstance(v, bool) or v <= 0):
            problems.append(f"{key} must be a number > 0")
    for k, v in (spec.get("vars") or {}).items():
        if not isinstance(v, list) or not v or not all(isinstance(x, (str, int, float)) for x in v):
            problems.append(f"vars.{k} must be a non-empty list of scalars to choose from")
    groups = spec.get("groups")
    if not isinstance(groups, list) or not groups:
        problems.append("groups must be a non-empty list")
    else:
        for i, g in enumerate(groups):
            if not isinstance(g, dict):
                problems.append(f"groups[{i}] must be an object")
                continue
            w = g.get("weight", 1.0)
            if not isinstance(w, (int, float)) or isinstance(w, bool) or w <= 0:
                problems.append(f"groups[{i}].weight must be a number > 0")
            cmds = g.get("commands")
            if not isinstance(cmds, list) or not cmds or not all(isinstance(c, str) and c.strip() for c in cmds):
                problems.append(f"groups[{i}].commands must be a non-empty list of command strings")
    if problems:
        raise RuntimeError(f"script generator {name!r}: " + "; ".join(problems))
    return spec


class ScriptKind(GeneratorKind):
    kind = "script"

    def render(self, plugin, cfg, spec: dict, env_spec, dest: Path) -> RenderedGenerator:
        resolved = {k: v for k, v in spec.items() if k != "generator"}
        resolved = expand_tokens(resolved, env_spec)
        scale_role = resolved.pop("scale_by_role", None)
        if scale_role is not None:
            n = len(_hosts_by_role(env_spec, scale_role))
            if n == 0:
                raise RuntimeError(f"script generator {resolved.get('name')!r}: scale_by_role {scale_role!r} "
                                   f"matches no host in this run")
            resolved["events_per_hour"] = float(resolved.get("events_per_hour", 0)) * n
        validate_script_spec(resolved)
        name = resolved["name"]
        user = resolved.get("user", "ubuntu")
        entry = resolved.get("entry", "direct")
        d = _spec_dir(dest, self.kind, name, spec)
        out = d / "spec.json"
        out.write_text(json.dumps(resolved, indent=2))
        g = RenderedGenerator(kind=self.kind, name=name, user="root" if entry == "ssh" else user, exec_start="")
        g.files = {"spec.json": str(out)}
        g.payloads = [str(_AUX / "script_runner.py")]
        g.log = f"{HOST_LOG_DIR}/{name}.jsonl"
        key_flag = f" --ssh-key {HOST_SSH_KEY}" if entry == "ssh" else ""
        g.exec_start = f"/usr/bin/python3 {g.dir}/script_runner.py --spec {g.dir}/spec.json --log {g.log}{key_flag}"
        g.check_cmd = f"/usr/bin/python3 {g.dir}/script_runner.py --spec {g.dir}/spec.json --check{key_flag}"
        if entry == "ssh":
            g.ssh_users = [user]
        return g


# -- ghosts_lite: CMU SEI GHOSTS Lite ---------------------------------------------------------------

class GhostsLiteKind(GeneratorKind):
    kind = "ghosts_lite"

    def render(self, plugin, cfg, spec: dict, env_spec, dest: Path) -> RenderedGenerator:
        name = _check_name(spec.get("name"), "ghosts_lite generator")
        timeline = spec.get("timeline")
        if isinstance(timeline, str):
            p = Path(timeline).expanduser()
            if not p.exists():
                raise RuntimeError(f"ghosts_lite generator {name!r}: timeline file {p} not found")
            timeline = json.loads(p.read_text())
        if not isinstance(timeline, dict) or not isinstance(timeline.get("TimeLineHandlers"), list):
            raise RuntimeError(f"ghosts_lite generator {name!r}: timeline must be an object with TimeLineHandlers")
        timeline = expand_tokens(timeline, env_spec)
        application = spec.get("application") or {
            "Id": "00000000-0000-0000-0000-000000000000", "Name": name, "IsEnabled": True, "IsDebug": False,
            "GhostsApiUri": "", "ResultsDisplay": "Local", "LoggingLevel": "none", "IsNodeSingle": True,
        }
        d = _spec_dir(dest, self.kind, name, spec)
        (d / "config").mkdir(exist_ok=True)
        app_f, tl_f = d / "config" / "application.json", d / "config" / "timeline.json"
        app_f.write_text(json.dumps(application, indent=2))
        tl_f.write_text(json.dumps(timeline, indent=2))
        g = RenderedGenerator(kind=self.kind, name=name, user=spec.get("user", "root"), exec_start="")
        g.files = {"config/application.json": str(app_f), "config/timeline.json": str(tl_f)}
        g.archive_url = spec.get("archive_url", DEFAULT_GHOSTS_LITE_URL)
        g.exec_start = f"{g.dir}/ghosts"
        g.check_cmd = f"test -x {g.dir}/ghosts"
        g.log = None   # GHOSTS Lite logs to its console: the unit's journal is its activity record
        return g


# -- computer_use: a Claude computer-use agent on the host's desktop (harness-side) ------------------

COMPUTER_USE_DEFAULT_MODEL = "claude-opus-5-5"
COMPUTER_USE_DEFAULT_DENY = [
    r"\bnmap\b", r"\bncat\b", r"\bnc\s+-", r"/etc/shadow", r"/etc/sudoers", r"\bdecoy", r"\bhoney",
    r"\bsudo\b", r"rm\s+-rf", r"\|\s*(ba)?sh\b", r"\bchmod\s+[0-7]*7[0-7]*\s", r"id_(rsa|ed25519)",
]


def validate_computer_use_spec(spec: dict) -> dict:
    """Shape-check a computer_use spec (shared with the harness-side driver). Returns the spec."""
    problems: list[str] = []
    name = spec.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        problems.append(f"name {name!r} must match {_NAME_RE.pattern}")
    if not isinstance(spec.get("persona", ""), str) or not spec.get("persona", "").strip():
        problems.append("persona must be a non-empty string (the system prompt describing the desktop user)")
    tasks = spec.get("tasks")
    if not isinstance(tasks, list) or not tasks or not all(isinstance(t, str) and t.strip() for t in tasks):
        problems.append("tasks must be a non-empty list of task strings (one is drawn per session)")
    rate = spec.get("sessions_per_hour")
    if not isinstance(rate, (int, float)) or isinstance(rate, bool) or rate <= 0:
        problems.append("sessions_per_hour must be a number > 0")
    steps = spec.get("max_steps", 30)
    if not isinstance(steps, int) or isinstance(steps, bool) or not 1 <= steps <= 200:
        problems.append("max_steps must be an int in 1..200")
    if spec.get("effort", "medium") not in ("low", "medium", "high", "xhigh", "max"):
        problems.append("effort must be one of low, medium, high, xhigh, max")
    for key in ("allowed_hosts", "deny_patterns"):
        v = spec.get(key)
        if v is not None and (not isinstance(v, list) or not all(isinstance(x, str) for x in v)):
            problems.append(f"{key} must be a list of strings")
    for k, v in (spec.get("vars") or {}).items():
        if not isinstance(v, list) or not v or not all(isinstance(x, (str, int, float)) for x in v):
            problems.append(f"vars.{k} must be a non-empty list of scalars to choose from")
    for pat in spec.get("deny_patterns") or []:
        try:
            re.compile(pat)
        except re.error as e:
            problems.append(f"deny_patterns: {pat!r} is not a valid regex ({e})")
    if problems:
        raise RuntimeError(f"computer_use generator {name!r}: " + "; ".join(problems))
    return spec


class ComputerUseKind(GeneratorKind):
    kind = "computer_use"

    def render(self, plugin, cfg, spec: dict, env_spec, dest: Path) -> RenderedGenerator:
        resolved = {k: v for k, v in spec.items() if k != "generator"}
        resolved = expand_tokens(resolved, env_spec)
        resolved.setdefault("model", COMPUTER_USE_DEFAULT_MODEL)
        resolved.setdefault("api_key_env", "ANTHROPIC_API_KEY")
        resolved.setdefault("display", ":1")
        resolved.setdefault("max_steps", 30)
        resolved.setdefault("effort", "medium")
        resolved.setdefault("deny_patterns", list(COMPUTER_USE_DEFAULT_DENY))
        # allowed_hosts defaults to the whole estate: the desktop user may reach any victim, never beyond
        if resolved.get("allowed_hosts") is None:
            resolved["allowed_hosts"] = sorted({h.ip for h in (env_spec.hosts if env_spec else []) if h.ip})
        validate_computer_use_spec(resolved)
        name = resolved["name"]
        d = _spec_dir(dest, self.kind, name, spec)
        out = d / "spec.json"
        out.write_text(json.dumps(resolved, indent=2))
        g = RenderedGenerator(kind=self.kind, name=name, user="-", exec_start="", side="harness")
        g.files = {"spec.json": str(out)}
        return g


# -- host vars for the play -------------------------------------------------------------------------

def hostvars_for(rendered: list[RenderedGenerator]) -> dict:
    """Flatten a host's generator list into the per-host vars aux/bgtraffic.yml loops over."""
    gens, files, payloads, archives, logs, ssh_users = [], [], [], [], [], set()
    for g in rendered:
        if g.side != "host":
            continue   # harness-side generators ship nothing to the host
        gens.append({"kind": g.kind, "name": g.name, "unit": g.unit, "dir": g.dir, "user": g.user,
                     "exec_start": g.exec_start, "check_cmd": g.check_cmd or "",
                     "log": g.log or "", "journal_log": "" if g.log else g.log_path})
        files += [{"src": src, "dest": f"{g.dir}/{rel}"} for rel, src in g.files.items()]
        payloads += [{"src": src, "dest": f"{g.dir}/"} for src in g.payloads]
        if g.archive_url:
            archives.append({"name": g.name, "url": g.archive_url, "dir": g.dir})
        logs.append({"name": g.name, "src": g.log_path})
        ssh_users.update(g.ssh_users)
    return {"bgtraffic_generators": gens, "bgtraffic_files": files, "bgtraffic_payloads": payloads,
            "bgtraffic_archives": archives, "bgtraffic_logs": logs, "bgtraffic_ssh_users": sorted(ssh_users)}
