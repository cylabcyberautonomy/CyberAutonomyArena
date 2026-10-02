#!/usr/bin/env python3
"""Experiment dashboard — reads the manager's live registry and serves a live HTML UI."""

import argparse
import html
import json
import os
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

EST = timezone(timedelta(hours=-5))

CONFIG_PATH = Path(__file__).parent / "config.yaml"
EXPERIMENT_SERVER = "http://localhost:8000/experiments"

# Matches ExperimentManagerConfig.output_dir's own default (_HERE / "output") - the
# dashboard has no access to that Pydantic config, so it's re-derived the same way:
# relative to this file's own location, since dashboard.py and config.py live in the
# same directory.
OUTPUT_ROOT = Path(__file__).parent / "output"

def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f) or {}

_cfg = _load_config()
MHBENCH_ENVIRONMENTS_DIR = (
    Path(_cfg["mhbench_dir"]) / "environments"
    if "mhbench_dir" in _cfg
    else Path("/tmp/missing-mhbench")
)
# Honor an explicit output_dir from config (arena points it at a custom path);
# the relative default above only applies when config doesn't set one. This drives
# the log viewer's file browsing and the Anthropic token_usage.json scan.
if _cfg.get("output_dir"):
    OUTPUT_ROOT = Path(_cfg["output_dir"])

# ── API usage tab: credentials ────────────────────────────────────────────────
# The dashboard is its own long-running process with no access to a plugin's env
# vars, so it reads them itself. Which repos to read, and which provider each one
# feeds, is NOT hardcoded here - it comes from config.yaml's `usage_sources` (see
# usage_json). This helper just parses one repo's .env given its config key.
def _load_repo_env(dir_key: str) -> dict:
    """Parse the .env at the root of the checkout config.yaml points to under
    dir_key. A missing config entry or a missing file yields {} - never a raise."""
    env: dict = {}
    repo_dir = _cfg.get(dir_key)
    if not repo_dir:
        return env
    env_path = Path(repo_dir) / ".env"
    if not env_path.exists():
        return env
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            env[key] = value
    return env

def _make_cred(env_dir_key: str | None, prefer_dotenv: bool):
    """A name->value resolver for one usage_source. The source names a repo via
    its config key (env_dir); the credential is read from that repo's .env and
    the process env. prefer_dotenv flips the precedence: the defender loads its
    own .env with override=True (to beat Incalmo's empty ANTHROPIC_API_KEY=''
    placeholder that the dashboard process may have inherited), so a source
    mirroring that sets prefer_dotenv: true to report the key actually in use.
    An empty value on either side falls through. The dashboard holds no repo or
    plugin name here - env_dir comes from config.yaml's usage_sources."""
    dotenv = _load_repo_env(env_dir_key) if env_dir_key else {}

    def cred(name: str) -> str | None:
        osv = os.environ.get(name)
        dv = dotenv.get(name)
        return (dv or osv or None) if prefer_dotenv else (osv or dv or None)
    return cred


def _get_json(url: str, headers: dict, params: dict | None = None) -> tuple[int, dict]:
    """GET url, return (status_code, parsed_json). Never raises - a connection
    failure comes back as (0, {"detail": "..."})  , matching the shape of an
    HTTP error response so callers can treat both uniformly."""
    if params:
        url = url + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = {"detail": e.reason}
        return e.code, body
    except Exception as e:
        return 0, {"detail": str(e)}


def _get_openrouter_usage(cred) -> dict:
    # /api/v1/key (singular) is OpenRouter's self-serve endpoint: the calling
    # key reports its OWN per-key limit/usage, no separate Provisioning key
    # needed. This is the per-key spend cap OpenRouter's key-edit page calls
    # "Credit limit" - distinct from (and more useful than) /api/v1/credits,
    # which is account-wide lifetime purchased-credits/usage, not this key's cap.
    api_key = cred("OPENROUTER_API_KEY")
    if not api_key:
        return {"limit": None, "limit_remaining": None, "usage": None, "error": "OPENROUTER_API_KEY not found"}

    status, body = _get_json(
        "https://openrouter.ai/api/v1/key",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    if status != 200:
        return {"limit": None, "limit_remaining": None, "usage": None, "error": f"OpenRouter returned {status}: {body}"}

    data = body.get("data") or {}
    # None (limit) means "no limit set" (unlimited key) - distinct from 0.
    return {"limit": data.get("limit"), "limit_remaining": data.get("limit_remaining"), "usage": data.get("usage"), "error": None}


def _get_litellm_usage(cred) -> dict:
    base_url = cred("LITELLM_BASE_URL")
    api_key = cred("LITELLM_API_KEY")
    if not base_url or not api_key:
        return {"spend": None, "max_budget": None, "error": "LITELLM_BASE_URL/LITELLM_API_KEY not found"}

    root = base_url.rstrip("/")
    if root.endswith("/v1"):
        root = root[: -len("/v1")]

    # Self-serve: LITELLM_API_KEY queries /key/info about itself. Requires that
    # key's allowed_routes include "/key/info" alongside its normal
    # llm_api_routes entry - a narrow, read-only grant added via (once, with a
    # master key): POST {root}/key/update {"key": "<key>", "allowed_routes":
    # ["llm_api_routes", "/key/info"]}.
    status, body = _get_json(f"{root}/key/info", headers={"Authorization": f"Bearer {api_key}"})
    if status != 200:
        return {"spend": None, "max_budget": None, "error": f"/key/info returned {status}: {body}"}

    info = body.get("info") or {}
    spend = body.get("spend", info.get("spend"))
    max_budget = body.get("max_budget", info.get("max_budget"))
    return {"spend": spend, "max_budget": max_budget, "error": None}


_ANTHROPIC_API_BASE = "https://api.anthropic.com"
_ANTHROPIC_VERSION = "2023-06-01"


def _mask_key(api_key: str) -> str:
    """Enough to tell two keys apart in the UI, not enough to use."""
    return f"\u2026{api_key[-4:]}" if len(api_key) >= 8 else "\u2026"


def _anthropic_key_status(api_key: str) -> tuple[bool, str | None]:
    """Is the defense repo's key still live? GET /v1/models is authenticated but
    free - it spends no tokens - so the tab can probe it on every 30s refresh.
    Returns (ok, error)."""
    status, body = _get_json(
        f"{_ANTHROPIC_API_BASE}/v1/models",
        headers={"x-api-key": api_key, "anthropic-version": _ANTHROPIC_VERSION},
        params={"limit": 1},
    )
    if status == 200:
        return True, None
    detail = (body.get("error") or {}).get("message") or body.get("detail") or body
    return False, f"key check returned {status}: {detail}"


def _anthropic_local_spend(output_root: Path) -> dict:
    """Spend on the defender's direct anthropic/ route, summed from the defender's
    own token_usage.json rows under output_root.

    Unlike the two cards above, this is NOT what the provider says the key spent.
    Anthropic has no self-serve per-key usage endpoint: OpenRouter's /api/v1/key and
    LiteLLM's /key/info both let a key ask about itself, but Anthropic's usage and
    cost reports live on the Admin API, which rejects a plain sk-ant-api key with
    401 "The Admin API requires an Admin API key or an organization-scoped API key".
    So the figure is reconstructed from what the defender logged - each row's `cost`
    is token counts x Anthropic list price, computed by LangChainRegistry
    .estimate_cost in the deception repo (which reprices cached input at Anthropic's
    cache rates). It tracks the bill, it is not the bill.

    Only rows the DEFENDER wrote count (parent dir "defender", at any depth under
    output/): the attacker's token_usage.json rows are Incalmo's spend on Incalmo's
    own credentials. Rows are matched on the "anthropic/" model prefix, which is
    exactly the routing prefix LangChainRegistry sends to the first-party API with
    ANTHROPIC_API_KEY - openrouter/ and litellm/ rows reach Anthropic models on
    somebody else's bill and must not be counted here."""
    empty = {"cost": None, "calls": 0, "unpriced": 0, "models": [], "latest": None}
    if not output_root.is_dir():
        return empty

    cost = 0.0
    calls = 0
    unpriced = 0
    models: set[str] = set()
    latest: str | None = None
    for path in output_root.rglob("token_usage.json"):
        if path.parent.name != "defender":
            continue
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue    # a row half-written by a live run - skip the row, not the file
            model = row.get("model") or ""
            if not model.startswith("anthropic/"):
                continue
            calls += 1
            models.add(model[len("anthropic/"):])
            row_cost = row.get("cost")
            if row_cost is None:
                unpriced += 1   # model absent from estimate_cost's price table
            else:
                cost += row_cost
            timestamp = row.get("timestamp")
            if timestamp and (latest is None or timestamp > latest):
                latest = timestamp

    if not calls:
        return empty
    return {"cost": cost, "calls": calls, "unpriced": unpriced,
            "models": sorted(models), "latest": latest}


def _get_anthropic_org_cost(admin_key: str) -> dict:
    """Month-to-date ORGANIZATION spend from the Admin Cost API - the only route to
    a real billed figure, and optional because it needs a separate credential:
    ANTHROPIC_ADMIN_KEY must hold an Admin key (sk-ant-admin...) or an org-scoped
    key. Absent that, the card falls back to the computed number above.

    Org-wide, not per-key: /v1/organizations/cost_report takes no api_key_ids filter
    (that lives on usage_report, which reports tokens rather than dollars), so this
    is an upper bound covering every other key in the org.

    UNVERIFIED against a live Admin key - none exists on this host. Two things to
    confirm when one does: that amounts sit at data[].results[].amount, and that
    they really are cents (the docs say "decimal strings in lowest units (cents)"),
    i.e. that dividing by 100 below is right."""
    now = datetime.now(timezone.utc)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    status, body = _get_json(
        f"{_ANTHROPIC_API_BASE}/v1/organizations/cost_report",
        headers={"x-api-key": admin_key, "anthropic-version": _ANTHROPIC_VERSION},
        params={
            "starting_at": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ending_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    )
    if status != 200:
        detail = (body.get("error") or {}).get("message") or body.get("detail") or body
        return {"cost": None, "error": f"cost_report returned {status}: {detail}"}

    cents = 0.0
    for bucket in body.get("data") or []:
        for result in bucket.get("results") or []:
            try:
                cents += float(result.get("amount") or 0)
            except (TypeError, ValueError):
                continue
    return {"cost": cents / 100, "error": None}


def _anthropic_budget(cred) -> float | None:
    """Optional spend cap, so this card can show the same spend-against-limit bar as
    the other two. Anthropic publishes no per-key limit of its own, so the number has
    to come from us: set ANTHROPIC_BUDGET_USD in the source's .env (or the dashboard's
    environment) to whatever the key was funded with."""
    raw = cred("ANTHROPIC_BUDGET_USD")
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def _get_anthropic_usage(cred, output_root: Path, scan_output: bool = False) -> dict:
    api_key = cred("ANTHROPIC_API_KEY")
    if not api_key:
        return {"key": None, "live": False, "local": None, "org": None,
                "budget": None, "error": "ANTHROPIC_API_KEY not found"}

    live, error = _anthropic_key_status(api_key)
    admin_key = cred("ANTHROPIC_ADMIN_KEY")
    return {
        "key": _mask_key(api_key),
        "live": live,
        "local": _anthropic_local_spend(output_root) if scan_output else None,
        "org": _get_anthropic_org_cost(admin_key) if admin_key else None,
        "budget": _anthropic_budget(cred),
        "error": error,
    }


# ── Plugin schema discovery ───────────────────────────────────────────────────
_HARNESS_DIR = Path(__file__).parent
if str(_HARNESS_DIR) not in sys.path:
    sys.path.insert(0, str(_HARNESS_DIR))

_ATTACKER_SCHEMAS: dict = {}
_DEFENDER_SCHEMAS: dict = {}
try:
    import arena.attacker.plugins   # triggers __init_subclass__ registration
    import arena.defender.plugins
    from arena.attacker.plugins.base import AttackerPlugin as _AtkBase
    from arena.defender.plugins.base import DefenderPlugin as _DefBase
    for _t, _cls in _AtkBase._registry.items():
        try:
            _ATTACKER_SCHEMAS[_t] = dict(_cls.ui_schema())
        except NotImplementedError:
            pass
    for _t, _cls in _DefBase._registry.items():
        try:
            _DEFENDER_SCHEMAS[_t] = dict(_cls.ui_schema())
        except NotImplementedError:
            pass
except Exception as _e:
    import warnings
    warnings.warn(f"Plugin schema discovery failed ({_e}); type dropdowns will be empty.")
# ─────────────────────────────────────────────────────────────────────────────



def load_experiments():
    # The manager keeps the registry in memory (the old experiment_registry.yaml
    # is never written), so read live state from its REST API. Return [] when the
    # backend is unreachable, so the dashboard still renders.
    try:
        req = urllib.request.Request(EXPERIMENT_SERVER, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return []

    def _parse_sort_ts(exp):
        # Prefer explicit submission time, then creation time.
        raw = exp.get("submitted_at") or exp.get("created_at")
        if not raw:
            return datetime.min.replace(tzinfo=timezone.utc)
        try:
            dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    experiments = data if isinstance(data, list) else data.get("experiments", [])
    return sorted(experiments, key=_parse_sort_ts, reverse=True)

def load_environments():
    """Return dict of group_name → sorted list of stems.
    Subdirectories become groups; JSON files directly in the root go under 'misc'."""
    groups = {}
    root = MHBENCH_ENVIRONMENTS_DIR
    if not root.exists():
        return groups
    for subdir in sorted(p for p in root.iterdir() if p.is_dir()):
        groups[subdir.name] = sorted(f.stem for f in subdir.glob("*.json"))
    misc = sorted(f.stem for f in root.glob("*.json"))
    if misc:
        groups["misc"] = misc
    return groups

# Short, legible nickname per environment spec ("group/stem" - see _env_panels()),
# used when the dashboard builds an experiment name out of the selected env. Same
# reasoning as the plugin `short_names` maps in ui_schema.py: experiment names become
# an SSH ControlPath component (mhbench-ssh/<experiment_name>/<hash>) and AF_UNIX
# socket paths cap out at 108 bytes, so a long env stem silently breaks every SSH
# connection. Specs with no entry here fall back to the plain stem (see submit JS) -
# add a nickname here rather than relying on that fallback for anything long.
ENV_NICKNAMES = {
    "non-generated/chain": "chain",
    "non-generated/chain_2hosts": "chain2h",
    "non-generated/chain_pe": "chain_pe",
    "non-generated/chain_pe_mixed": "chain_pemix",
    "non-generated/dumbbell": "dumbbell",
    "non-generated/dumbbell_pe": "dumbbell_pe",
    "non-generated/enterprise_a": "ent_a",
    "non-generated/enterprise_b": "ent_b",
    "non-generated/equifax_large": "eq_large",
    "non-generated/equifax_medium": "eq_medium",
    "non-generated/equifax_small": "eq_small",
    "non-generated/ics": "ics",
    "non-generated/star": "star",
    "non-generated/star_pe": "star_pe",
    "non-generated/sudobaron_test": "sudobaron",
    "instrumented/equifax_small_instrumented": "eq_small_i",
    "generated/generated_mini": "gen_mini",
    **{f"generated/generated_network_{i}": f"gennet{i}" for i in range(30)},
}



_LOG_VIEWER_MAX_BYTES = 500_000  # tail-truncate anything bigger, rather than ship huge payloads

def _experiment_output_dir(name: str) -> Path:
    return OUTPUT_ROOT / name

def list_experiment_files(name: str) -> list[str]:
    """Relative file paths under this experiment's output dir, sorted. Empty list (not an error) if
    the experiment has no output yet or the name doesn't resolve to a real directory under OUTPUT_ROOT."""
    base = _experiment_output_dir(name)
    try:
        base = base.resolve()
        base.relative_to(OUTPUT_ROOT.resolve())
    except (ValueError, OSError):
        return []
    if not base.is_dir():
        return []
    return sorted(str(p.relative_to(base)) for p in base.rglob("*") if p.is_file())

def read_experiment_file(name: str, rel_path: str) -> tuple[bool, str]:
    """Returns (ok, content-or-error-message). Guards path traversal - the resolved target must stay
    under this specific experiment's own output dir, whatever `rel_path` claims."""
    base = _experiment_output_dir(name)
    try:
        base = base.resolve()
        target = (base / rel_path).resolve()
        target.relative_to(base)
    except (ValueError, OSError):
        return False, "Invalid path"
    if not target.is_file():
        return False, "File not found"
    try:
        size = target.stat().st_size
        with open(target, "rb") as f:
            if size > _LOG_VIEWER_MAX_BYTES:
                f.seek(size - _LOG_VIEWER_MAX_BYTES)
                content = f.read().decode("utf-8", errors="replace")
                content = (
                    f"... [truncated - showing the last {_LOG_VIEWER_MAX_BYTES:,} "
                    f"of {size:,} bytes] ...\n" + content
                )
            else:
                content = f.read().decode("utf-8", errors="replace")
        return True, content
    except OSError as e:
        return False, f"Error reading file: {e}"

def _stat_experiment_file(name: str, rel_path: str):
    """(size, mtime) for the same path read_experiment_file() would read, or None if it doesn't
    resolve to a real file under this experiment's output dir. Used to detect whether a log
    actually changed without re-reading (and re-shipping) its full content on every poll."""
    base = _experiment_output_dir(name)
    try:
        base = base.resolve()
        target = (base / rel_path).resolve()
        target.relative_to(base)
    except (ValueError, OSError):
        return None
    try:
        st = target.stat()
        return st.st_size, st.st_mtime
    except OSError:
        return None

_LOG_WAIT_TIMEOUT_S = 25.0   # long-poll ceiling; client reconnects immediately after
_LOG_WAIT_POLL_S = 0.5       # how often we stat() the file while waiting for it to change

def wait_for_experiment_file_change(name: str, rel_path: str, since_size, since_mtime) -> dict:
    """Blocks (up to _LOG_WAIT_TIMEOUT_S) until (size, mtime) differs from what the client last
    saw, then returns fresh content - this is what lets the log viewer refresh "when the log
    changes" rather than on a blind timer. since_size/since_mtime arrive as query-string strings
    (or None on a client's first call for a file), so comparisons below are string vs str(int/float)."""
    deadline = time.monotonic() + _LOG_WAIT_TIMEOUT_S
    while True:
        st = _stat_experiment_file(name, rel_path)
        if st is None:
            # File vanished (e.g. rotated) - report unconditionally rather than looping forever.
            ok, content = read_experiment_file(name, rel_path)
            return {"changed": True, "ok": ok, "content": content, "size": None, "mtime": None}
        size, mtime = st
        changed = since_size is None or since_mtime is None or str(size) != since_size or str(mtime) != since_mtime
        if changed or time.monotonic() >= deadline:
            ok, content = read_experiment_file(name, rel_path)
            return {"changed": changed, "ok": ok, "content": content, "size": size, "mtime": mtime}
        time.sleep(_LOG_WAIT_POLL_S)


# ── Submit-shape adapters (arena wire format) ─────────────────────────────────
# The browser builds the generic, backend-agnostic form from each plugin's
# ui_schema(): environment as a spec string, attacker/defender as embedded
# {type, ...}. The arena manager, however, takes the explicit {environment_plugin,
# environment_spec} for the environment and a (plugin, spec) pair for the attacker
# (the embedded 'attacker' block is rejected). Adapt here, server-side on the
# manager's own host, so the frontend stays plugin/backend-agnostic. Defender keeps
# its embedded {type, ...} form, so it passes through untouched.
def _topology_spec(spec: str) -> str:
    """The env picker's value is the <group>/<stem> the listing was built from (so the
    nickname/display map keys line up). mhbench's resolve_topology_path wants the real
    path relative to mhbench_dir - environments/<group>/<stem>.json, the same subtree
    load_environments() reads - with no library-name resolution. Normalize here, unless
    the value is already an absolute path or a full environments/*.json path."""
    if spec.startswith("/") or (spec.startswith("environments/") and spec.endswith(".json")):
        return spec
    return f"environments/{spec}.json"


def _environment_to_config(payload: dict) -> dict:
    env = payload.get("environment")
    if isinstance(env, str):
        payload = {**payload, "environment": {
            "environment_plugin": _cfg.get("environment_plugin", "mhbench"),
            "environment_spec": _topology_spec(env),
        }}
    return payload


def _attacker_to_plugin_spec(payload: dict) -> dict:
    """Embedded attacker {type, ...fields} -> attacker_plugin + attacker_spec (an
    inline dict of the bespoke fields; the manager injects the type). The arena
    model accepts attacker_spec as an inline dict or a file path - inline keeps
    the dashboard stateless (no spec files to write, name, or clean up)."""
    atk = payload.get("attacker")
    if isinstance(atk, dict) and atk.get("type"):
        payload = {k: v for k, v in payload.items() if k != "attacker"}
        payload["attacker_plugin"] = atk["type"]
        payload["attacker_spec"] = {k: v for k, v in atk.items() if k != "type"}
    return payload


def proxy_submit(payload: dict) -> tuple[int, dict]:
    payload = _attacker_to_plugin_spec(_environment_to_config(payload))
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        EXPERIMENT_SERVER,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = {"detail": e.reason}
        return e.code, body
    except Exception as e:
        return 500, {"detail": str(e)}



# ─────────────────────────────────────────────────────────────────────────────
# Thin JSON backend
#
# All rendering lives in dashboard_static/{index.html,app.css,app.js}; the server
# only (a) serves those static files, (b) exposes the data the browser cannot get
# on its own - plugin/env schemas (need the Python plugin registry), API-usage
# aggregation (needs secret keys + the token_usage.json scan), and log-file reads
# (need the local filesystem) - and (c) proxies the manager's experiment CRUD so
# the manager URL stays server-side and there is no cross-origin dance.
# ─────────────────────────────────────────────────────────────────────────────

import mimetypes

STATIC_DIR = Path(__file__).parent / "dashboard_static"
_STATIC_TYPES = {".html": "text/html; charset=utf-8",
                 ".css": "text/css; charset=utf-8",
                 ".js": "application/javascript; charset=utf-8",
                 ".svg": "image/svg+xml"}


# Generic provider adapters. The dashboard knows how to talk to these LLM
# providers; it does NOT know which plugin or repo uses them - that mapping is
# declared per deployment in config.yaml's `usage_sources`.
_USAGE_ADAPTERS = {
    "openrouter": lambda cred, src: _get_openrouter_usage(cred),
    "litellm":    lambda cred, src: _get_litellm_usage(cred),
    "anthropic":  lambda cred, src: _get_anthropic_usage(
        cred, OUTPUT_ROOT, scan_output=bool(src.get("scan_output"))),
}


def usage_json() -> dict:
    """Spend per configured source. Each entry of config.yaml's `usage_sources`
    names a generic provider adapter plus the repo (env_dir) whose .env holds the
    credentials; the dashboard renders whatever the adapters return. No provider,
    repo, or plugin name is hardcoded here."""
    sources = []
    for src in (_cfg.get("usage_sources") or []):
        provider = src.get("provider")
        label = src.get("label") or (provider or "unknown").replace("_", " ").title()
        adapter = _USAGE_ADAPTERS.get(provider)
        if adapter is None:
            data = {"error": f"unknown provider '{provider}' (known: {', '.join(sorted(_USAGE_ADAPTERS))})"}
        else:
            cred = _make_cred(src.get("env_dir"), bool(src.get("prefer_dotenv")))
            data = adapter(cred, src)
        sources.append({"provider": provider, "label": label, "data": data})
    return {"sources": sources}


def schemas_json() -> dict:
    """Plugin UI-schema contract + env nickname map that drive the Submit form."""
    return {
        "attacker": _ATTACKER_SCHEMAS,
        "defender": _DEFENDER_SCHEMAS,
        "env_nicknames": ENV_NICKNAMES,
    }


def proxy_priority(name: str, priority: int) -> tuple[int, dict]:
    data = json.dumps({"priority": priority}).encode()
    req = urllib.request.Request(
        f"{EXPERIMENT_SERVER}/{urllib.parse.quote(name)}/priority",
        data=data, headers={"Content-Type": "application/json"}, method="POST",
    )
    return _proxy_call(req)


def proxy_delete(name: str) -> tuple[int, dict]:
    req = urllib.request.Request(
        f"{EXPERIMENT_SERVER}/{urllib.parse.quote(name)}", method="DELETE",
    )
    return _proxy_call(req)


def _proxy_call(req) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = {"detail": e.reason}
        return e.code, body
    except Exception as e:
        return 500, {"detail": str(e)}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence request logs

    def _respond(self, code, content_type, body):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        try:
            self.wfile.write(b)
        except (BrokenPipeError, ConnectionResetError):
            pass  # client navigated away mid-response (common with long-poll)

    def _json(self, code, obj):
        self._respond(code, "application/json", json.dumps(obj, default=str))

    def _serve_static(self, rel: str):
        # rel is already path-safe (only [a-zA-Z0-9._-], no slashes) by the caller.
        path = (STATIC_DIR / rel).resolve()
        if not str(path).startswith(str(STATIC_DIR.resolve())) or not path.is_file():
            self._respond(404, "text/plain", "Not found")
            return
        ctype = _STATIC_TYPES.get(path.suffix) or mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        self._respond(200, ctype, path.read_bytes())

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if route == "/":
            self._serve_static("index.html")
        elif route.startswith("/static/"):
            name = route[len("/static/"):]
            if "/" in name or ".." in name:
                self._respond(404, "text/plain", "Not found")
            else:
                self._serve_static(name)
        elif route == "/api/experiments":
            self._json(200, {"experiments": load_experiments()})
        elif route == "/api/usage":
            self._json(200, usage_json())
        elif route == "/api/schema":
            self._json(200, schemas_json())
        elif route == "/api/environments":
            self._json(200, load_environments())
        # ── log viewer (filesystem reads; kept verbatim from the old server) ──
        elif route == "/experiment_files":
            name = (qs.get("name") or [""])[0]
            self._json(200, {"files": list_experiment_files(name)})
        elif route == "/experiment_file_wait":
            name = (qs.get("name") or [""])[0]
            rel_path = (qs.get("path") or [""])[0]
            since_size = (qs.get("since_size") or [None])[0]
            since_mtime = (qs.get("since_mtime") or [None])[0]
            self._json(200, wait_for_experiment_file_change(name, rel_path, since_size, since_mtime))
        elif route == "/experiment_file":
            name = (qs.get("name") or [""])[0]
            rel_path = (qs.get("path") or [""])[0]
            ok, content = read_experiment_file(name, rel_path)
            if ok:
                size, mtime = _stat_experiment_file(name, rel_path) or (None, None)
                self._json(200, {"content": content, "size": size, "mtime": mtime})
            else:
                self._json(404, {"error": content})
        else:
            self._respond(404, "text/plain", "Not found")

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        return json.loads(raw) if raw else {}

    def do_POST(self):
        route = urllib.parse.urlparse(self.path).path
        try:
            payload = self._read_json_body()
        except Exception:
            self._json(400, {"detail": "Invalid JSON"})
            return

        if route == "/api/submit":
            status, result = proxy_submit(payload)
            self._json(status, result)
        elif route.startswith("/api/experiments/") and route.endswith("/priority"):
            name = urllib.parse.unquote(route[len("/api/experiments/"):-len("/priority")])
            try:
                priority = int(payload.get("priority"))
            except (TypeError, ValueError):
                self._json(422, {"detail": "priority must be an integer"})
                return
            status, result = proxy_priority(name, priority)
            self._json(status, result)
        else:
            self._respond(404, "text/plain", "Not found")

    def do_DELETE(self):
        route = urllib.parse.urlparse(self.path).path
        if route.startswith("/api/experiments/"):
            name = urllib.parse.unquote(route[len("/api/experiments/"):])
            status, result = proxy_delete(name)
            self._json(status, result)
        else:
            self._respond(404, "text/plain", "Not found")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Experiment dashboard server")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    ThreadingHTTPServer.allow_reuse_address = True
    # Threading matters for /experiment_file_wait: it long-polls (blocks up to
    # _LOG_WAIT_TIMEOUT_S inside the request), so every other viewer's refresh and
    # log tail would stall behind it on a single-threaded HTTPServer.
    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"Dashboard running at http://localhost:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
