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

# ── API usage tab: OpenRouter / LiteLLM credentials ───────────────────────────
# This dashboard is its own long-running process, separate from Incalmo - it has
# no access to Incalmo's own env vars unless we read them ourselves. Incalmo's
# .env lives under incalmo_dir (already in config.yaml, since the Incalmo
# attacker plugin drives that same checkout). A bare OS env var of the same name
# wins if set directly on the dashboard process, so a deployment can override
# without touching Incalmo's .env.
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

_incalmo_env = _load_repo_env("incalmo_dir")

# The defender's credentials live in the deception repo's own .env, NOT Incalmo's:
# Incalmo's .env carries an empty ANTHROPIC_API_KEY='' placeholder, and the defender
# loads its own .env with override=True specifically to beat it (see the deception
# repo's defender/agents/langchain_registry.py). Reading Incalmo's .env here would
# report that placeholder as the defense repo's key.
_deception_env = _load_repo_env("deception_dir")

def _credential(name: str) -> str | None:
    return os.environ.get(name) or _incalmo_env.get(name) or None


def _defense_credential(name: str) -> str | None:
    """Credential as the DEFENDER resolves it. .env first, then the process env -
    the reverse of _credential's precedence, mirroring the defender's own
    load_dotenv(override=True) so this reports the key actually in use. An empty
    value on either side falls through, so an inherited ANTHROPIC_API_KEY='' can't
    shadow the real one."""
    return _deception_env.get(name) or os.environ.get(name) or None


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


def _get_openrouter_usage() -> dict:
    # /api/v1/key (singular) is OpenRouter's self-serve endpoint: the calling
    # key reports its OWN per-key limit/usage, no separate Provisioning key
    # needed. This is the per-key spend cap OpenRouter's key-edit page calls
    # "Credit limit" - distinct from (and more useful than) /api/v1/credits,
    # which is account-wide lifetime purchased-credits/usage, not this key's cap.
    api_key = _credential("OPENROUTER_API_KEY")
    if not api_key:
        return {"limit": None, "limit_remaining": None, "usage": None, "error": "OPENROUTER_API_KEY not found in Incalmo's .env"}

    status, body = _get_json(
        "https://openrouter.ai/api/v1/key",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    if status != 200:
        return {"limit": None, "limit_remaining": None, "usage": None, "error": f"OpenRouter returned {status}: {body}"}

    data = body.get("data") or {}
    # None (limit) means "no limit set" (unlimited key) - distinct from 0.
    return {"limit": data.get("limit"), "limit_remaining": data.get("limit_remaining"), "usage": data.get("usage"), "error": None}


def _get_litellm_usage() -> dict:
    base_url = _credential("LITELLM_BASE_URL")
    api_key = _credential("LITELLM_API_KEY")
    if not base_url or not api_key:
        return {"spend": None, "max_budget": None, "error": "LITELLM_BASE_URL/LITELLM_API_KEY not found in Incalmo's .env"}

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


def _anthropic_local_spend() -> dict:
    """Spend on the defender's direct anthropic/ route, summed from the defender's
    own token_usage.json rows under OUTPUT_ROOT.

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
    if not OUTPUT_ROOT.is_dir():
        return empty

    cost = 0.0
    calls = 0
    unpriced = 0
    models: set[str] = set()
    latest: str | None = None
    for path in OUTPUT_ROOT.rglob("token_usage.json"):
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


def _anthropic_budget() -> float | None:
    """Optional spend cap, so this card can show the same spend-against-limit bar as
    the other two. Anthropic publishes no per-key limit of its own, so the number has
    to come from us: set ANTHROPIC_BUDGET_USD in the deception repo's .env (or the
    dashboard's environment) to whatever the key was funded with."""
    raw = _defense_credential("ANTHROPIC_BUDGET_USD")
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def _get_anthropic_usage() -> dict:
    api_key = _defense_credential("ANTHROPIC_API_KEY")
    if not api_key:
        return {"key": None, "live": False, "local": None, "org": None,
                "budget": None, "error": "ANTHROPIC_API_KEY not found in the deception repo's .env"}

    live, error = _anthropic_key_status(api_key)
    admin_key = _defense_credential("ANTHROPIC_ADMIN_KEY")
    return {
        "key": _mask_key(api_key),
        "live": live,
        "local": _anthropic_local_spend(),
        "org": _get_anthropic_org_cost(admin_key) if admin_key else None,
        "budget": _anthropic_budget(),
        "error": error,
    }


def _anthropic_html(anthropic: dict) -> str:
    """The Anthropic card. Shaped like the other two - spend, optional bar, errors -
    but with the key's own liveness on top, since a revoked or exhausted key is the
    failure this card exists to catch: the defender swallows its LLM errors on a
    thread pool, so a dead key shows up as a silent defender, not as a crash."""
    if anthropic["key"] is None:
        return f"""
    <div class="usage-card">
      <h2>Anthropic (defense repo)</h2>
      <div class="usage-error">{html.escape(anthropic["error"])}</div>
    </div>"""

    local = anthropic["local"]
    budget = anthropic["budget"]
    key_state = "live" if anthropic["live"] else "not accepted"
    budget_suffix = f" / {_fmt_usd(budget)}" if budget else ""

    calls_row = ""
    if local["calls"]:
        models = ", ".join(local["models"])
        unpriced = f" · {local['unpriced']} unpriced" if local["unpriced"] else ""
        calls_row = (f'<div class="usage-row"><span>Calls</span>'
                     f'<strong>{local["calls"]} · {html.escape(models)}{unpriced}</strong></div>')

    org = anthropic["org"]
    org_row = ""
    if org and org["cost"] is not None:
        org_row = ('<div class="usage-row"><span>Org spend (month to date)</span>'
                   f'<strong>{_fmt_usd(org["cost"])}</strong></div>')

    bar_html = _usage_bar_html(local["cost"], budget) if budget else ""
    error_html = (f'<div class="usage-error">{html.escape(anthropic["error"])}</div>'
                  if anthropic["error"] else "")
    if org and org["error"]:
        error_html += f'<div class="usage-error">{html.escape(org["error"])}</div>'

    note = ("Anthropic exposes no self-serve per-key usage endpoint, so this is summed "
            "from the defender's own token_usage.json rows (tokens \u00d7 list price) - it "
            "tracks the bill rather than being it. Set ANTHROPIC_ADMIN_KEY for billed "
            "org totals, ANTHROPIC_BUDGET_USD for a limit bar.")

    return f"""
    <div class="usage-card">
      <h2>Anthropic (defense repo)</h2>
      <div class="usage-row"><span>Key</span><strong>{html.escape(anthropic["key"])} · {key_state}</strong></div>
      <div class="usage-row"><span>Spend (computed)</span><strong>{_fmt_usd(local["cost"])}{budget_suffix}</strong></div>
      {bar_html}
      {calls_row}
      {org_row}
      <div class="usage-note">{note}</div>
      {error_html}
    </div>"""


def _fmt_usd(value) -> str:
    return "—" if value is None else f"${value:.4f}"


def _usage_bar_html(spend, limit) -> str:
    """A progress bar for spend against a per-key limit, or a note that no
    limit is set. Shared by both cards - same shape of cap on both sides now
    that OpenRouter's /api/v1/key exposes a real per-key limit, like LiteLLM's
    max_budget."""
    if spend is None or not limit:
        return '<div class="usage-note">No limit set on this key.</div>' if spend is not None else ""
    pct = min(100.0, (spend / limit) * 100)
    warn = " warn" if pct > 90 else ""
    return f'<div class="usage-bar-track"><div class="usage-bar-fill{warn}" style="width:{pct:.1f}%"></div></div>'


def _usage_html() -> str:
    openrouter = _get_openrouter_usage()
    litellm = _get_litellm_usage()
    anthropic = _get_anthropic_usage()

    or_error_html = f'<div class="usage-error">{html.escape(openrouter["error"])}</div>' if openrouter["error"] else ""
    or_limit_suffix = f' / {_fmt_usd(openrouter["limit"])}' if openrouter["limit"] else ""
    or_bar_html = _usage_bar_html(openrouter["usage"], openrouter["limit"])

    llm_error_html = f'<div class="usage-error">{html.escape(litellm["error"])}</div>' if litellm["error"] else ""
    llm_budget_suffix = f' / {_fmt_usd(litellm["max_budget"])}' if litellm["max_budget"] else ""
    llm_bar_html = _usage_bar_html(litellm["spend"], litellm["max_budget"])

    return f"""
    <div class="usage-card">
      <h2>OpenRouter</h2>
      <div class="usage-row"><span>Usage</span><strong>{_fmt_usd(openrouter["usage"])}{or_limit_suffix}</strong></div>
      {or_bar_html}
      {or_error_html}
    </div>
    <div class="usage-card">
      <h2>LiteLLM (CMU gateway)</h2>
      <div class="usage-row"><span>Spend</span><strong>{_fmt_usd(litellm["spend"])}{llm_budget_suffix}</strong></div>
      {llm_bar_html}
      {llm_error_html}
    </div>{_anthropic_html(anthropic)}"""


# ── Plugin schema discovery ───────────────────────────────────────────────────
_HARNESS_DIR = Path(__file__).parent
if str(_HARNESS_DIR) not in sys.path:
    sys.path.insert(0, str(_HARNESS_DIR))

_ATTACKER_SCHEMAS: dict = {}
_DEFENDER_SCHEMAS: dict = {}
try:
    import experiment_manager.attacker.plugins   # triggers __init_subclass__ registration
    import experiment_manager.defender.plugins
    from experiment_manager.attacker.plugins.base import AttackerPlugin as _AtkBase
    from experiment_manager.defender.plugins.base import DefenderPlugin as _DefBase
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


def fmt_time(raw):
    if not raw or raw == "—":
        return "—"
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00")).astimezone(EST)
        return dt.strftime("%b %-d, %-I:%M %p EST")
    except Exception:
        return str(raw)


STATUS_STYLE = {
    "Queued":    ("⬜", "#6b7280", "#f3f4f6"),
    "Deploying": ("🔵", "#2563eb", "#dbeafe"),
    "Running":   ("🟡", "#d97706", "#fef3c7"),
    "Error":     ("🔴", "#dc2626", "#fee2e2"),
    "Finished":  ("✅", "#059669", "#d1fae5"),
    "TimedOut":  ("⏱️", "#b45309", "#fef3c7"),
    "Blocked":   ("🚫", "#7c3aed", "#ede9fe"),
}

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

def status_counts(experiments):
    counts = {s: 0 for s in STATUS_STYLE}
    for e in experiments:
        s = e.get("status", "Queued")
        counts[s] = counts.get(s, 0) + 1
    return counts

def _plugin_schemas_js() -> str:
    atk_json = json.dumps(_ATTACKER_SCHEMAS, indent=2)
    def_json = json.dumps(_DEFENDER_SCHEMAS, indent=2)
    env_json = json.dumps(ENV_NICKNAMES, indent=2)
    return (f"  <script>\n    const ATTACKER_SCHEMAS = {atk_json};\n    const DEFENDER_SCHEMAS = {def_json};\n"
            f"    const ENV_NICKNAMES = {env_json};\n  </script>")

def _error_html(e: dict) -> str:
    """Truncated failure reason under the status badge - click to expand the full text
    (native <details>/<summary>, hover still shows it too via title). Shown only for
    failed states that carry a reason."""
    err = e.get("error")
    status = e.get("status")
    if not err or status not in ("Error", "TimedOut", "Blocked"):
        return ""
    # Match the reason text to the status: red only for the actual Error state; the soft terminal
    # states (TimedOut / Blocked) use their own badge colour so they don't read as a hard failure.
    color = {"Error": "#dc2626", "TimedOut": "#b45309", "Blocked": "#7c3aed"}[status]
    safe = html.escape(str(err))
    return (f'<details class="err-details" style="color:{color}">'
            f'<summary title="{safe}">{safe}</summary>'
            f'<div class="err-full">{safe}</div>'
            f'</details>')


def _error_html(e: dict) -> str:
    """Truncated failure reason under the status badge - click to expand the full text
    (native <details>/<summary>, hover still shows it too via title). Shown only for
    failed states that carry a reason."""
    err = e.get("error")
    if not err or e.get("status") not in ("Error", "TimedOut"):
        return ""
    safe = html.escape(str(err))
    return (f'<details class="err-details" style="color:#dc2626">'
            f'<summary title="{safe}">{safe}</summary>'
            f'<div class="err-full">{safe}</div>'
            f'</details>')


def render_html(experiments):
    counts = status_counts(experiments)
    total = len(experiments)

    summary_cards = ""
    for status, (icon, color, bg) in STATUS_STYLE.items():
        n = counts.get(status, 0)
        summary_cards += f"""
        <div class="summary-card" style="border-left:4px solid {color};background:{bg}">
          <div class="summary-count" style="color:{color}">{n}</div>
          <div class="summary-label" style="color:{color}">{icon} {status}</div>
        </div>"""

    rows = ""
    for e in experiments:
        name = e.get("experiment_name", "—")
        status = e.get("status", "Queued")
        env = e.get("environment_spec", "—")
        attacker = (e.get("attacker") or {}).get("strategy", "—")
        updated = fmt_time(e.get("updated_at"))
        created = fmt_time(e.get("created_at"))
        retries = e.get("retry_count", 0)
        icon, color, bg = STATUS_STYLE.get(status, ("⬜", "#6b7280", "#f3f4f6"))
        badge = f'<span class="badge" style="background:{bg};color:{color};border:1px solid {color}">{icon} {status}</span>'
        retry_html = f' <span class="retry-badge">↩ {retries}</span>' if retries else ""
        err_html = _error_html(e)
        rows += f"""
        <tr>
          <td class="name-cell">{name}</td>
          <td>{badge}{retry_html}{err_html}</td>
          <td>{env}</td>
          <td>{attacker}</td>
          <td class="time-cell">{created}</td>
          <td class="time-cell">{updated}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Experiment Dashboard</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #0f172a; color: #e2e8f0; min-height: 100vh; }}
    header {{ background: #1e293b; border-bottom: 1px solid #334155;
              padding: 1rem 2rem; display: flex; align-items: center; justify-content: space-between; }}
    header h1 {{ font-size: 1.25rem; font-weight: 700; color: #f8fafc; }}
    header .meta {{ font-size: 0.8rem; color: #94a3b8; }}
    .tabs {{ display: flex; gap: 0; padding: 0 2rem; border-bottom: 1px solid #334155;
             background: #1e293b; }}
    .tab {{ padding: 0.75rem 1.5rem; cursor: pointer; font-size: 0.88rem; font-weight: 600;
            color: #64748b; border-bottom: 2px solid transparent; transition: all 0.15s; }}
    .tab:hover {{ color: #e2e8f0; }}
    .tab.active {{ color: #f8fafc; border-bottom-color: #3b82f6; }}
    .tab-panel {{ display: none; }}
    .tab-panel.active {{ display: block; }}
    .summary {{ display: flex; gap: 1rem; padding: 1.5rem 2rem; flex-wrap: wrap; }}
    .summary-card {{ flex: 1; min-width: 120px; padding: 1rem 1.25rem; border-radius: 8px; }}
    .summary-count {{ font-size: 2rem; font-weight: 800; line-height: 1; }}
    .summary-label {{ font-size: 0.8rem; margin-top: 0.25rem; font-weight: 600; }}
    .table-wrap {{ padding: 0 2rem 2rem; overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b;
             border-radius: 10px; overflow: hidden; font-size: 0.88rem; }}
    thead th {{ background: #0f172a; color: #94a3b8; text-transform: uppercase;
                font-size: 0.72rem; letter-spacing: 0.08em; padding: 0.75rem 1rem; text-align: left; }}
    tbody tr {{ border-top: 1px solid #334155; transition: background 0.15s; }}
    tbody tr:hover {{ background: #263048; }}
    td {{ padding: 0.65rem 1rem; vertical-align: middle; }}
    .name-cell {{ font-family: monospace; font-size: 0.82rem; color: #cbd5e1; max-width: 280px;
                  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
    .time-cell {{ color: #64748b; font-size: 0.8rem; white-space: nowrap; }}
    .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 999px;
              font-size: 0.78rem; font-weight: 600; white-space: nowrap; }}
    .retry-badge {{ display: inline-block; margin-left: 4px; padding: 0.1rem 0.45rem;
                    border-radius: 999px; background: #334155; color: #94a3b8; font-size: 0.72rem; }}
    /* Error reason under a status badge: collapsed to one truncated line by default,
       click to expand the full text (native <details>, no extra JS needed). */
    .err-details {{ margin-top: 4px; font-size: 0.72rem; max-width: 380px; }}
    .err-details summary {{ cursor: pointer; list-style: none; overflow: hidden;
                             text-overflow: ellipsis; white-space: nowrap; }}
    .err-details summary::-webkit-details-marker {{ display: none; }}
    .err-details summary::before {{ content: '▸ '; }}
    .err-details[open] summary::before {{ content: '▾ '; }}
    .err-full {{ margin-top: 4px; padding: 0.5rem 0.6rem; background: rgba(0,0,0,0.25);
                 border-radius: 6px; color: #e2e8f0; font-family: monospace; font-size: 0.72rem;
                 white-space: pre-wrap; word-break: break-word; max-width: 480px; }}
    .refresh-bar {{ display: flex; align-items: center; gap: 0.5rem; }}
    .dot {{ width: 8px; height: 8px; border-radius: 50%; background: #22c55e;
            animation: pulse 2s infinite; display: inline-block; }}
    @keyframes pulse {{ 0%,100%{{opacity:1}} 50%{{opacity:0.3}} }}
    .total {{ color: #94a3b8; font-size: 0.8rem; padding: 0 2rem 0.5rem;}}

    /* Log viewer: VSCode-style split view, opened by clicking an experiment row */
    .exp-row {{ cursor: pointer; }}
    .exp-row:hover {{ background: rgba(255,255,255,0.04); }}
    .log-viewer-overlay {{
      display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6);
      z-index: 1000; align-items: center; justify-content: center;
    }}
    .log-viewer-overlay.open {{ display: flex; }}
    .log-viewer-modal {{
      width: 92vw; height: 88vh; background: #0f172a; border: 1px solid #334155;
      border-radius: 10px; display: flex; flex-direction: column; overflow: hidden;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    }}
    .log-viewer-header {{
      display: flex; align-items: center; justify-content: space-between;
      padding: 0.75rem 1rem; background: #1e293b; border-bottom: 1px solid #334155;
    }}
    .log-viewer-header .title {{ font-family: monospace; font-size: 0.85rem; color: #f8fafc; }}
    .log-viewer-header .title .sub {{ color: #64748b; margin-left: 0.5rem; }}
    .log-viewer-actions {{ display: flex; align-items: center; gap: 0.6rem; }}
    .log-viewer-refresh-label {{ font-size: 0.72rem; color: #94a3b8; display: flex; align-items: center; gap: 0.3rem; }}
    .log-viewer-close {{
      background: none; border: 1px solid #334155; color: #94a3b8; border-radius: 6px;
      cursor: pointer; font-size: 0.9rem; padding: 0.2rem 0.55rem; line-height: 1;
    }}
    .log-viewer-close:hover {{ color: #e2e8f0; border-color: #64748b; }}
    .log-viewer-body {{ flex: 1; display: flex; min-height: 0; }}
    .log-viewer-files {{
      width: 260px; flex-shrink: 0; overflow-y: auto; border-right: 1px solid #334155;
      background: #131c2e; padding: 0.5rem 0;
    }}
    .log-viewer-file {{
      padding: 0.35rem 1rem; font-family: monospace; font-size: 0.78rem; color: #94a3b8;
      cursor: pointer; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }}
    .log-viewer-file:hover {{ background: rgba(255,255,255,0.04); color: #cbd5e1; }}
    .log-viewer-file.selected {{ background: #1e3a5f; color: #e2e8f0; border-left: 2px solid #3b82f6; }}
    .log-viewer-empty {{ padding: 1rem; font-size: 0.78rem; color: #64748b; }}
    .log-viewer-content {{
      flex: 1; margin: 0; padding: 1rem; overflow: auto; background: #0a0f1a;
      color: #cbd5e1; font-family: monospace; font-size: 0.78rem; white-space: pre-wrap;
      word-break: break-word;
    }}

    /* Submit tab */
    .submit-wrap {{ padding: 2rem; }}
    .form-section {{ background: #1e293b; border-radius: 10px; padding: 1.5rem; margin-bottom: 1.5rem; }}
    .form-section h2 {{ font-size: 0.95rem; font-weight: 700; color: #f8fafc; margin-bottom: 1rem;
                        border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }}
    .form-row {{ display: flex; gap: 1rem; align-items: flex-start; flex-wrap: wrap; margin-bottom: 0.75rem; }}
    .form-group {{ display: flex; flex-direction: column; gap: 0.3rem; flex: 1; min-width: 160px; }}
    .form-group label {{ font-size: 0.78rem; font-weight: 600; color: #94a3b8; text-transform: uppercase;
                         letter-spacing: 0.05em; }}
    .form-group input, .form-group select {{
      background: #0f172a; border: 1px solid #334155; border-radius: 6px;
      color: #e2e8f0; padding: 0.5rem 0.75rem; font-size: 0.88rem; font-family: inherit;
      transition: border-color 0.15s; }}
    .form-group input:focus, .form-group select:focus {{
      outline: none; border-color: #3b82f6; }}
    .env-layout {{ display: flex; gap: 1rem; align-items: flex-start; }}
    .env-picker {{ flex: 1; min-width: 0; }}
    .env-selected-panel {{ width: 220px; flex-shrink: 0; background: #0f172a; border: 1px solid #334155;
                           border-radius: 8px; padding: 0.75rem; }}
    .env-selected-panel h3 {{ font-size: 0.75rem; font-weight: 700; color: #64748b;
                              text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 0.6rem; }}
    .env-chips {{ display: flex; flex-direction: column; gap: 0.35rem; max-height: 260px; overflow-y: auto; }}
    .env-chip {{ display: flex; align-items: center; justify-content: space-between; gap: 0.4rem;
                 background: #1e293b; border: 1px solid #334155; border-radius: 5px;
                 padding: 0.3rem 0.5rem; }}
    .env-chip-label {{ font-size: 0.78rem; font-family: monospace; color: #cbd5e1;
                       white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
    .env-chip-remove {{ background: none; border: none; color: #64748b; cursor: pointer;
                        font-size: 0.9rem; line-height: 1; padding: 0; flex-shrink: 0; }}
    .env-chip-remove:hover {{ color: #f87171; }}
    .env-empty-note {{ font-size: 0.78rem; color: #475569; font-style: italic; }}
    .env-group-panel {{ display: none; }}
    .env-group-panel.active {{ display: block; }}
    .env-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(190px, 1fr)); gap: 0.3rem;
                 max-height: 260px; overflow-y: auto; padding-right: 0.25rem; }}
    .env-item {{ display: flex; align-items: center; gap: 0.5rem; padding: 0.35rem 0.5rem;
                 border-radius: 5px; cursor: pointer; transition: background 0.1s; }}
    .env-item:hover {{ background: #263048; }}
    .env-item input[type=checkbox] {{ accent-color: #3b82f6; width: 14px; height: 14px;
                                      cursor: pointer; flex-shrink: 0; }}
    .env-item label {{ font-size: 0.82rem; font-family: monospace; color: #cbd5e1; cursor: pointer; }}
    .env-controls {{ display: flex; gap: 0.5rem; margin-bottom: 0.75rem; align-items: center; }}
    .btn-sm {{ padding: 0.3rem 0.75rem; border-radius: 5px; border: 1px solid #334155;
               background: #263048; color: #94a3b8; font-size: 0.78rem; cursor: pointer; transition: all 0.15s; }}
    .btn-sm:hover {{ background: #334155; color: #e2e8f0; }}
    .config-layout {{ display: flex; gap: 1rem; align-items: flex-start; }}
    .config-form {{ flex: 1; min-width: 0; }}
    .config-list-panel {{ width: 220px; flex-shrink: 0; background: #0f172a; border: 1px solid #334155;
                          border-radius: 8px; padding: 0.75rem; }}
    .config-list-panel h3 {{ font-size: 0.75rem; font-weight: 700; color: #64748b;
                             text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 0.6rem; }}
    .config-chips {{ display: flex; flex-direction: column; gap: 0.35rem; max-height: 200px; overflow-y: auto; }}
    .config-chip {{ display: flex; align-items: center; justify-content: space-between; gap: 0.4rem;
                    background: #1e293b; border: 1px solid #334155; border-radius: 5px;
                    padding: 0.3rem 0.5rem; }}
    .config-chip-label {{ font-size: 0.78rem; font-family: monospace; color: #cbd5e1;
                          white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
    .config-chip-remove {{ background: none; border: none; color: #64748b; cursor: pointer;
                           font-size: 0.9rem; line-height: 1; padding: 0; flex-shrink: 0; }}
    .config-chip-remove:hover {{ color: #f87171; }}
    .add-btn {{ margin-top: 0.75rem; padding: 0.4rem 1rem; background: #1d4ed8; color: #e2e8f0;
                font-size: 0.82rem; font-weight: 600; border: none; border-radius: 6px;
                cursor: pointer; transition: background 0.15s; }}
    .add-btn:hover {{ background: #2563eb; }}
    .llm-check-grid {{ background: #0f172a; border: 1px solid #334155; border-radius: 6px;
                       padding: 0.4rem 0.5rem; max-height: 200px; overflow-y: auto; overflow-x: hidden; }}
    .llm-group-label {{ font-size: 0.68rem; color: #475569; text-transform: uppercase;
                        letter-spacing: 0.06em; padding: 0.3rem 0.25rem 0.1rem;
                        margin-top: 0.3rem; display: block; }}
    .llm-group-label:first-child {{ margin-top: 0; }}
    .llm-group-block {{ display: flex; flex-direction: column; gap: 0.15rem; }}
    .llm-group-head {{ display: flex; align-items: center; justify-content: space-between;
               gap: 0.5rem; padding: 0.1rem 0.25rem 0; }}
    .llm-group-controls {{ display: flex; gap: 0.35rem; flex-shrink: 0; }}
    .llm-item {{ display: flex; align-items: center; gap: 0.4rem; padding: 0.2rem 0.25rem;
                 border-radius: 4px; cursor: pointer; transition: background 0.1s; }}
    .llm-item:hover {{ background: #263048; }}
    .llm-item input[type=checkbox] {{ accent-color: #3b82f6; width: 13px; height: 13px;
                                      cursor: pointer; flex-shrink: 0; }}
    .llm-item label {{ font-size: 0.78rem; font-family: monospace; color: #cbd5e1; cursor: pointer;
                       word-break: break-all; }}
    .llm-controls {{ display: flex; justify-content: flex-end; margin-top: 0.35rem; }}
    .llm-select-all, .llm-clear {{ border: 1px solid #334155; background: #263048; color: #94a3b8;
          border-radius: 5px; cursor: pointer; transition: all 0.15s;
          font-size: 0.75rem; padding: 0.3rem 0.55rem; }}
    .llm-select-all:hover, .llm-clear:hover {{ background: #334155; color: #e2e8f0; }}
    .kv-pairs {{ background: #0f172a; border: 1px solid #334155; border-radius: 6px;
           padding: 0.45rem; display: flex; flex-direction: column; gap: 0.4rem; }}
    .kv-pairs-header, .kv-pair-row {{ display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto;
                      gap: 0.45rem; align-items: center; }}
    .kv-pairs-header {{ font-size: 0.68rem; color: #475569; text-transform: uppercase;
              letter-spacing: 0.06em; padding: 0 0.15rem; }}
    .kv-pair-row input {{ min-width: 0; }}
    .kv-pair-add, .kv-pair-remove {{ border: 1px solid #334155; background: #263048; color: #94a3b8;
                      border-radius: 5px; cursor: pointer; transition: all 0.15s;
                      font-size: 0.78rem; padding: 0.35rem 0.6rem; }}
    .kv-pair-add:hover, .kv-pair-remove:hover {{ background: #334155; color: #e2e8f0; }}
    .kv-pairs-controls {{ display: flex; justify-content: flex-start; }}
    .submit-btn {{ padding: 0.65rem 2rem; background: #3b82f6; color: #fff; font-weight: 700;
                   font-size: 0.9rem; border: none; border-radius: 7px; cursor: pointer; transition: background 0.15s; }}
    .submit-btn:hover {{ background: #2563eb; }}
    .submit-btn:disabled {{ background: #334155; color: #64748b; cursor: not-allowed; }}
    .results-box {{ margin-top: 1.5rem; background: #0f172a; border-radius: 8px; padding: 1rem;
                    font-family: monospace; font-size: 0.82rem; max-height: 300px; overflow-y: auto;
                    border: 1px solid #334155; display: none; }}
    .results-box.visible {{ display: block; }}
    .result-ok {{ color: #34d399; }}
    .result-err {{ color: #f87171; }}
    .result-info {{ color: #94a3b8; }}

    /* API Usage tab */
    .usage-wrap {{ padding: 2rem; max-width: 640px; }}
    .usage-card {{ background: #1e293b; border-radius: 10px; padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; }}
    .usage-card h2 {{ font-size: 0.95rem; font-weight: 700; color: #f8fafc; margin-bottom: 0.75rem;
                      border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }}
    .usage-row {{ display: flex; justify-content: space-between; padding: 0.3rem 0; font-size: 0.88rem; color: #cbd5e1; }}
    .usage-row strong {{ color: #f8fafc; }}
    .usage-bar-track {{ background: #0f172a; border-radius: 999px; height: 8px; margin-top: 0.5rem; overflow: hidden; }}
    .usage-bar-fill {{ height: 100%; background: #3b82f6; border-radius: 999px; transition: width 0.3s; }}
    .usage-bar-fill.warn {{ background: #dc2626; }}
    .usage-error {{ color: #f87171; font-size: 0.82rem; margin-top: 0.4rem; }}
    .usage-updated {{ color: #64748b; font-size: 0.78rem; margin-bottom: 1rem; }}
    .usage-note {{ color: #64748b; font-size: 0.78rem; font-style: italic; margin-top: 0.4rem; }}
  </style>
{_plugin_schemas_js()}
  <script>
    // ── Dashboard tab auto-refresh ──────────────────────────────────────────
    function autoRefresh() {{
      fetch('/data')
        .then(r => r.json())
        .then(data => {{
          document.getElementById('dashboard-root').innerHTML = data.html;
          document.getElementById('ts').textContent = new Date().toLocaleTimeString();
        }});
    }}
    setInterval(autoRefresh, 5000);

    // ── API Usage tab auto-refresh ──────────────────────────────────────────
    function autoRefreshUsage() {{
      fetch('/api_usage')
        .then(r => r.json())
        .then(data => {{
          document.getElementById('usage-root').innerHTML = data.html;
          document.getElementById('usage-ts').textContent = new Date().toLocaleTimeString();
        }});
    }}
    autoRefreshUsage();
    setInterval(autoRefreshUsage, 30000);

    document.addEventListener('DOMContentLoaded', () => {{
      document.getElementById('ts').textContent = new Date().toLocaleTimeString();

      // ── Tab switching ─────────────────────────────────────────────────────
      document.querySelectorAll('.tab').forEach(tab => {{
        tab.addEventListener('click', () => {{
          document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
          document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
          tab.classList.add('active');
          document.getElementById(tab.dataset.panel).classList.add('active');
        }});
      }});

      // ── Log viewer: click an experiment row to browse its output-dir files ──
      // #dashboard-root's own innerHTML gets replaced wholesale on every 5s
      // autoRefresh() poll, so this listens on the (never-replaced) root itself
      // and delegates to whichever .exp-row was actually clicked, rather than
      // attaching one listener per row that autoRefresh would just tear down.
      let logViewerExpName = null;
      let logViewerFilePath = null;
      // (size, mtime) of the file as last rendered - what /experiment_file_wait compares
      // against server-side to decide whether anything actually changed.
      let logViewerSize = null;
      let logViewerMtime = null;
      let logViewerWaitController = null;   // AbortController for the in-flight long-poll
      let logViewerWaitRetryTimer = null;   // backoff timer after a failed long-poll

      const overlay = document.getElementById('log-viewer-overlay');
      const filesPane = document.getElementById('log-viewer-files');
      const contentPane = document.getElementById('log-viewer-content');

      // "At the bottom" (within a few px, to tolerate rounding) means tail-follow this
      // update; anywhere else means the reader scrolled up on purpose, so leave them be.
      function isAtBottom() {{
        return contentPane.scrollHeight - contentPane.scrollTop - contentPane.clientHeight < 30;
      }}

      function stopLogViewerWait() {{
        if (logViewerWaitController) {{ logViewerWaitController.abort(); logViewerWaitController = null; }}
        if (logViewerWaitRetryTimer) {{ clearTimeout(logViewerWaitRetryTimer); logViewerWaitRetryTimer = null; }}
      }}

      function closeLogViewer() {{
        overlay.classList.remove('open');
        logViewerExpName = null;
        logViewerFilePath = null;
        logViewerSize = null;
        logViewerMtime = null;
        stopLogViewerWait();
        document.getElementById('log-viewer-autorefresh').checked = false;
      }}
      document.getElementById('log-viewer-close').addEventListener('click', closeLogViewer);
      overlay.addEventListener('click', e => {{ if (e.target === overlay) closeLogViewer(); }});
      document.addEventListener('keydown', e => {{
        if (e.key === 'Escape' && overlay.classList.contains('open')) closeLogViewer();
      }});

      // Long-polls /experiment_file_wait, which blocks server-side until the file's (size,
      // mtime) differ from what we last saw (or times out) - this is what makes the viewer
      // refresh "on a change in the log" rather than on a blind interval. Each call chains
      // the next on completion, for as long as this same file stays open and "Live" is on.
      function pollForChanges(path) {{
        stopLogViewerWait();
        if (!document.getElementById('log-viewer-autorefresh').checked || logViewerFilePath !== path) return;
        const controller = new AbortController();
        logViewerWaitController = controller;
        const params = new URLSearchParams({{
          name: logViewerExpName, path,
          since_size: logViewerSize, since_mtime: logViewerMtime,
        }});
        fetch(`/experiment_file_wait?${{params}}`, {{signal: controller.signal}})
          .then(r => r.json())
          .then(data => {{
            logViewerSize = data.size;
            logViewerMtime = data.mtime;
            if (data.changed) {{
              const wasAtBottom = isAtBottom();
              contentPane.textContent = data.ok ? data.content : `[${{data.error}}]`;
              if (wasAtBottom) contentPane.scrollTop = contentPane.scrollHeight;
            }}
            pollForChanges(path);
          }})
          .catch(err => {{
            if (err.name === 'AbortError') return;  // superseded by a newer call - not a failure
            // Transient (e.g. a dashboard restart) - back off briefly rather than hammering it.
            logViewerWaitRetryTimer = setTimeout(() => pollForChanges(path), 3000);
          }});
      }}

      function loadLogFile(path) {{
        logViewerFilePath = path;
        logViewerSize = null;
        logViewerMtime = null;
        stopLogViewerWait();
        filesPane.querySelectorAll('.log-viewer-file').forEach(el => {{
          el.classList.toggle('selected', el.dataset.path === path);
        }});
        document.getElementById('log-viewer-file-name').textContent = ' — ' + path;
        contentPane.textContent = 'Loading…';
        fetch(`/experiment_file?name=${{encodeURIComponent(logViewerExpName)}}&path=${{encodeURIComponent(path)}}`)
          .then(r => r.json())
          .then(data => {{
            // A file that vanished mid-view (e.g. rotated) is reported, not silently blanked.
            contentPane.textContent = data.content !== undefined ? data.content : `[${{data.error}}]`;
            logViewerSize = data.size;
            logViewerMtime = data.mtime;
            // Logs are read newest-line-last - opening a file (as opposed to a later
            // change-triggered update) always jumps to the bottom, like `tail -f`.
            contentPane.scrollTop = contentPane.scrollHeight;
            pollForChanges(path);
          }})
          .catch(err => {{ contentPane.textContent = `[Error loading file: ${{err}}]`; }});
      }}

      function openLogViewer(name) {{
        logViewerExpName = name;
        document.getElementById('log-viewer-name').textContent = name;
        document.getElementById('log-viewer-file-name').textContent = '';
        contentPane.textContent = 'Select a file on the left to view its contents.';
        filesPane.innerHTML = 'Loading…';
        overlay.classList.add('open');
        fetch(`/experiment_files?name=${{encodeURIComponent(name)}}`)
          .then(r => r.json())
          .then(data => {{
            if (!data.files || data.files.length === 0) {{
              filesPane.innerHTML = '<div class="log-viewer-empty">No output files yet.</div>';
              return;
            }}
            filesPane.innerHTML = '';
            data.files.forEach(path => {{
              const el = document.createElement('div');
              el.className = 'log-viewer-file';
              el.dataset.path = path;
              el.title = path;
              el.textContent = path;
              el.addEventListener('click', () => loadLogFile(path));
              filesPane.appendChild(el);
            }});
          }});
      }}

      document.getElementById('dashboard-root').addEventListener('click', e => {{
        // Clicking the error-details <summary> should just toggle it open/closed,
        // not also pop the log viewer on top of it.
        if (e.target.closest('.err-details')) return;
        const row = e.target.closest('.exp-row');
        if (row) openLogViewer(row.dataset.name);
      }});

      document.getElementById('log-viewer-autorefresh').addEventListener('change', e => {{
        if (e.target.checked) {{
          if (logViewerFilePath) pollForChanges(logViewerFilePath);
        }} else {{
          stopLogViewerWait();
        }}
      }});

      // ── Environment picker ────────────────────────────────────────────────
      const selectedEnvs = new Map(); // envSpec → display label

      function renderEnvChips() {{
        const chips = document.getElementById('env-chips');
        const empty = document.getElementById('env-chips-empty');
        const count = document.getElementById('env-selected-count');
        chips.innerHTML = '';
        if (selectedEnvs.size === 0) {{
          empty.style.display = '';
        }} else {{
          empty.style.display = 'none';
          selectedEnvs.forEach((label, spec) => {{
            const chip = document.createElement('div');
            chip.className = 'env-chip';
            chip.innerHTML = `<span class="env-chip-label" title="${{spec}}">${{label}}</span>
              <button type="button" class="env-chip-remove" data-spec="${{spec}}">✕</button>`;
            chips.appendChild(chip);
          }});
        }}
        count.textContent = selectedEnvs.size ? ` (${{selectedEnvs.size}})` : '';
      }}

      document.getElementById('env-chips').addEventListener('click', e => {{
        const btn = e.target.closest('.env-chip-remove');
        if (!btn) return;
        const spec = btn.dataset.spec;
        selectedEnvs.delete(spec);
        const cb = document.querySelector(`.env-cb[value="${{spec}}"]`);
        if (cb) cb.checked = false;
        renderEnvChips();
      }});

      document.getElementById('env-group-select').addEventListener('change', function() {{
        document.querySelectorAll('.env-group-panel').forEach(p => p.classList.remove('active'));
        const panel = document.getElementById('env-group-' + this.value);
        if (panel) panel.classList.add('active');
      }});
      document.getElementById('env-group-select').dispatchEvent(new Event('change'));

      document.getElementById('env-select-all').addEventListener('click', () => {{
        const activeGroup = document.getElementById('env-group-select').value;
        document.querySelectorAll(`#env-group-${{activeGroup}} .env-cb`).forEach(cb => {{
          cb.checked = true;
          selectedEnvs.set(cb.value, cb.dataset.label);
        }});
        renderEnvChips();
      }});
      document.getElementById('env-clear').addEventListener('click', () => {{
        const activeGroup = document.getElementById('env-group-select').value;
        document.querySelectorAll(`#env-group-${{activeGroup}} .env-cb`).forEach(cb => {{
          cb.checked = false;
          selectedEnvs.delete(cb.value);
        }});
        renderEnvChips();
      }});
      document.getElementById('env-panels').addEventListener('change', e => {{
        if (!e.target.classList.contains('env-cb')) return;
        const cb = e.target;
        if (cb.checked) selectedEnvs.set(cb.value, cb.dataset.label);
        else selectedEnvs.delete(cb.value);
        renderEnvChips();
      }});

      // ── Generic plugin form renderer ──────────────────────────────────────

      function buildTypeDropdown(selectEl, schemas) {{
        selectEl.innerHTML = '';
        for (const [configType, schema] of Object.entries(schemas)) {{
          const opt = document.createElement('option');
          opt.value = configType;
          opt.textContent = schema.label || configType;
          selectEl.appendChild(opt);
        }}
      }}

      function renderFields(containerEl, schema) {{
        containerEl.innerHTML = '';
        if (!schema) return;
        const row = document.createElement('div');
        row.className = 'form-row';
        row.style.alignItems = 'stretch';

        for (const field of schema.fields) {{
          const grp = document.createElement('div');
          grp.className = 'form-group';
          grp.dataset.fieldKey = field.key;
          if (field.show_when) {{
            grp.dataset.showWhen = JSON.stringify(field.show_when);
          }}

          const lbl = document.createElement('label');
          lbl.textContent = field.label;
          grp.appendChild(lbl);

          if (field.field_type === 'text_with_suggestions') {{
            const listId = `dl-${{schema.config_type}}-${{field.key}}`;
            const input = document.createElement('input');
            input.setAttribute('list', listId);
            input.value = field.default || '';
            input.placeholder = field.suggestions[0] || '';
            input.dataset.fieldKey = field.key;
            input.dataset.fieldType = field.field_type;
            const dl = document.createElement('datalist');
            dl.id = listId;
            for (const s of (field.suggestions || [])) {{
              const opt = document.createElement('option');
              opt.value = s;
              dl.appendChild(opt);
            }}
            grp.appendChild(input);
            grp.appendChild(dl);

          }} else if (field.field_type === 'flat_checkboxes') {{
            const grid = document.createElement('div');
            grid.className = 'llm-check-grid';
            grid.dataset.fieldKey = field.key;
            grid.dataset.fieldType = field.field_type;
            for (const opt of (field.options || [])) {{
              const safe = opt.replace(/[^a-z0-9]/gi, '-');
              const cbId = `cb-${{schema.config_type}}-${{field.key}}-${{safe}}`;
              const item = document.createElement('div');
              item.className = 'llm-item';
              item.innerHTML = `<input type="checkbox" class="llm-cb" id="${{cbId}}" value="${{opt}}">` +
                               `<label for="${{cbId}}">${{opt}}</label>`;
              grid.appendChild(item);
            }}
            const controls = document.createElement('div');
            controls.className = 'llm-controls';
            controls.innerHTML = '<button type="button" class="llm-select-all">Select all</button> ' +
                                 '<button type="button" class="llm-clear">Clear</button>';
            grid.appendChild(controls);
            grid.addEventListener('click', (event) => {{
              if (event.target.classList.contains('llm-select-all')) {{
                grid.querySelectorAll('.llm-cb').forEach(cb => {{ cb.checked = true; }});
              }} else if (event.target.classList.contains('llm-clear')) {{
                grid.querySelectorAll('.llm-cb').forEach(cb => {{ cb.checked = false; }});
              }} else {{
                return;
              }}
            }});
            grp.appendChild(grid);

          }} else if (field.field_type === 'grouped_checkboxes') {{
            const grid = document.createElement('div');
            grid.className = 'llm-check-grid';
            grid.dataset.fieldKey = field.key;
            grid.dataset.fieldType = field.field_type;
            for (const [groupIndex, grpDef] of (field.groups || []).entries()) {{
              const groupBlock = document.createElement('div');
              groupBlock.className = 'llm-group-block';
              groupBlock.dataset.groupIndex = String(groupIndex);

              const head = document.createElement('div');
              head.className = 'llm-group-head';

              const hdr = document.createElement('span');
              hdr.className = 'llm-group-label';
              hdr.textContent = grpDef.group_label;
              head.appendChild(hdr);

              const controls = document.createElement('div');
              controls.className = 'llm-group-controls';
              controls.innerHTML = '<button type="button" class="llm-select-all">Select all</button> ' +
                                   '<button type="button" class="llm-clear">Clear</button>';
              head.appendChild(controls);

              groupBlock.appendChild(head);
              for (const opt of grpDef.options) {{
                const safe = opt.replace(/[^a-z0-9]/gi, '-');
                const cbId = `cb-${{schema.config_type}}-${{field.key}}-${{safe}}`;
                const item = document.createElement('div');
                item.className = 'llm-item';
                item.innerHTML = `<input type="checkbox" class="llm-cb" id="${{cbId}}" value="${{opt}}">` +
                                 `<label for="${{cbId}}">${{opt}}</label>`;
                groupBlock.appendChild(item);
              }}
              grid.appendChild(groupBlock);
            }}
            grid.addEventListener('click', (event) => {{
              const btn = event.target.closest('.llm-select-all, .llm-clear');
              if (!btn) return;
              const groupBlock = btn.closest('.llm-group-block');
              if (!groupBlock) return;
              if (btn.classList.contains('llm-select-all')) {{
                groupBlock.querySelectorAll('.llm-cb').forEach(cb => {{ cb.checked = true; }});
              }} else if (btn.classList.contains('llm-clear')) {{
                groupBlock.querySelectorAll('.llm-cb').forEach(cb => {{ cb.checked = false; }});
              }} else {{
                return;
              }}
            }});
            grp.appendChild(grid);

          }} else if (field.field_type === 'key_value_pairs') {{
            const grid = document.createElement('div');
            grid.className = 'kv-pairs';
            grid.dataset.fieldKey = field.key;
            grid.dataset.fieldType = field.field_type;

            const header = document.createElement('div');
            header.className = 'kv-pairs-header';
            header.innerHTML = '<span>Key</span><span>Value</span><span></span>';
            grid.appendChild(header);

            const addRow = (keyValue = {{ key: '', value: '' }}) => {{
              const row = document.createElement('div');
              row.className = 'kv-pair-row';
              row.innerHTML = `
                <input type="text" class="kv-pair-key" placeholder="${{field.key_placeholder || 'name'}}" value="${{keyValue.key || ''}}">
                <input type="text" class="kv-pair-value" placeholder="${{field.value_placeholder || 'value'}}" value="${{keyValue.value || ''}}">
                <button type="button" class="kv-pair-remove">Remove</button>
              `;
              grid.appendChild(row);
            }};

            for (const entry of (field.entries || [])) {{
              addRow(entry);
            }}
            if (!(field.entries || []).length) addRow();

            const controls = document.createElement('div');
            controls.className = 'kv-pairs-controls';
            controls.innerHTML = '<button type="button" class="kv-pair-add">+ Add row</button>';
            grid.appendChild(controls);

            grid.addEventListener('click', (event) => {{
              if (event.target.classList.contains('kv-pair-add')) {{
                addRow();
              }} else if (event.target.classList.contains('kv-pair-remove')) {{
                const row = event.target.closest('.kv-pair-row');
                if (row) row.remove();
              }}
            }});

            grp.appendChild(grid);

          }} else if (field.field_type === 'json') {{
            const input = document.createElement('input');
            input.placeholder = field.placeholder || '{{}}';
            input.value = field.default || '';
            input.dataset.fieldKey = field.key;
            input.dataset.fieldType = field.field_type;
            grp.appendChild(input);
          }}

          row.appendChild(grp);
        }}
        containerEl.appendChild(row);

        // Conditional field visibility (show_when): re-evaluate on any change or
        // click (checkbox toggles, select-all/clear buttons), then once now.
        // Attach the delegated listeners once per container (renderFields runs
        // again on every type switch, but the container element persists).
        if (!containerEl.dataset.showWhenBound) {{
          containerEl.addEventListener('change', () => applyConditionalVisibility(containerEl));
          containerEl.addEventListener('click', () => applyConditionalVisibility(containerEl));
          containerEl.dataset.showWhenBound = '1';
        }}
        applyConditionalVisibility(containerEl);
      }}

      // Current form values as fieldKey -> array of selected/entered values.
      function currentFieldValues(containerEl) {{
        const vals = {{}};
        containerEl.querySelectorAll('[data-field-type="flat_checkboxes"],[data-field-type="grouped_checkboxes"]').forEach(grid => {{
          vals[grid.dataset.fieldKey] = [...grid.querySelectorAll('.llm-cb:checked')].map(cb => cb.value);
        }});
        containerEl.querySelectorAll('input[data-field-key]').forEach(input => {{
          vals[input.dataset.fieldKey] = [input.value.trim()];
        }});
        return vals;
      }}

      // Show/hide fields with a show_when condition based on current values.
      // Visible iff, for every controlling key, at least one selected value is
      // in that key's allowed list (OR within a key, AND across keys).
      function applyConditionalVisibility(containerEl) {{
        const vals = currentFieldValues(containerEl);
        containerEl.querySelectorAll('.form-group[data-show-when]').forEach(grp => {{
          let cond;
          try {{ cond = JSON.parse(grp.dataset.showWhen); }} catch (ex) {{ return; }}
          let visible = true;
          for (const [ctrlKey, allowed] of Object.entries(cond)) {{
            const cur = vals[ctrlKey] || [];
            if (!cur.some(v => allowed.includes(v))) {{ visible = false; break; }}
          }}
          grp.style.display = visible ? '' : 'none';
        }});
      }}

      function readFieldValues(containerEl) {{
        const result = {{}};
        containerEl.querySelectorAll('input[data-field-key]').forEach(input => {{
          if (input.closest('.form-group')?.style.display === 'none') return;
          result[input.dataset.fieldKey] = {{ type: input.dataset.fieldType, value: input.value.trim() }};
        }});
        containerEl.querySelectorAll('[data-field-type="flat_checkboxes"],[data-field-type="grouped_checkboxes"]').forEach(grid => {{
          if (grid.closest('.form-group')?.style.display === 'none') return;
          result[grid.dataset.fieldKey] = {{
            type: grid.dataset.fieldType,
            value: [...grid.querySelectorAll('.llm-cb:checked')].map(cb => cb.value),
          }};
        }});
        containerEl.querySelectorAll('[data-field-type="key_value_pairs"]').forEach(grid => {{
          if (grid.closest('.form-group')?.style.display === 'none') return;
          result[grid.dataset.fieldKey] = {{
            type: grid.dataset.fieldType,
            value: [...grid.querySelectorAll('.kv-pair-row')].map(row => ({{
              key: row.querySelector('.kv-pair-key').value.trim(),
              value: row.querySelector('.kv-pair-value').value.trim(),
            }})),
          }};
        }});
        return result;
      }}

      function cartesianProduct(arrays) {{
        return arrays.reduce(
          (acc, arr) => acc.flatMap(combo => arr.map(v => [...combo, v])),
          [[]]
        );
      }}

      function buildConfigs(configType, schema, fieldValues) {{
        // Only fields present in fieldValues are considered; readFieldValues
        // omits fields hidden by show_when, so they are neither required nor
        // emitted (the plugin supplies their default).
        const present  = f => Object.prototype.hasOwnProperty.call(fieldValues, f.key);
        const cbKeys   = schema.fields.filter(f => present(f) && (f.field_type === 'flat_checkboxes' || f.field_type === 'grouped_checkboxes')).map(f => f.key);
        const textKeys = schema.fields.filter(f => present(f) && (f.field_type === 'text_with_suggestions' || f.field_type === 'json')).map(f => f.key);
        const kvKeys   = schema.fields.filter(f => present(f) && f.field_type === 'key_value_pairs').map(f => f.key);

        // Resolve text/json values (shared across all combos)
        const fixedVals = {{}};
        for (const key of textKeys) {{
          const raw = (fieldValues[key] || {{}}).value || '';
          const fieldDef = schema.fields.find(f => f.key === key);
          if (fieldDef && fieldDef.field_type === 'json') {{
            if (raw) {{
              try {{ fixedVals[key] = JSON.parse(raw); }}
              catch(ex) {{ alert(`${{fieldDef.label}} JSON is invalid: ${{ex.message}}`); return null; }}
            }} else {{
              fixedVals[key] = {{}};
            }}
          }} else {{
            fixedVals[key] = raw || (fieldDef && fieldDef.default) || '';
          }}
        }}

        for (const key of kvKeys) {{
          const rows = (fieldValues[key] || {{}}).value || [];
          const objectValue = {{}};
          for (const row of rows) {{
            const entryKey = (row.key || '').trim();
            const entryValue = (row.value || '').trim();
            if (!entryKey && !entryValue) continue;
            if (!entryKey || !entryValue) {{
              const fieldDef = schema.fields.find(f => f.key === key);
              alert(`Fill in both key and value for "${{fieldDef ? fieldDef.label : key}}".`);
              return null;
            }}
            const parsed = Number(entryValue);
            if (!Number.isInteger(parsed)) {{
              const fieldDef = schema.fields.find(f => f.key === key);
              alert(`Value for "${{entryKey}}" in "${{fieldDef ? fieldDef.label : key}}" must be an integer.`);
              return null;
            }}
            if (Object.prototype.hasOwnProperty.call(objectValue, entryKey)) {{
              const fieldDef = schema.fields.find(f => f.key === key);
              alert(`Duplicate key "${{entryKey}}" in "${{fieldDef ? fieldDef.label : key}}".`);
              return null;
            }}
            objectValue[entryKey] = parsed;
          }}
          if (!Object.keys(objectValue).length) {{
            const fieldDef = schema.fields.find(f => f.key === key);
            alert(`Add at least one key/value pair for "${{fieldDef ? fieldDef.label : key}}".`);
            return null;
          }}
          fixedVals[key] = objectValue;
        }}

        if (schema.cartesian_product) {{
          const arrays = [];
          for (const key of cbKeys) {{
            const vals = (fieldValues[key] || {{}}).value || [];
            if (!vals.length) {{
              const fieldDef = schema.fields.find(f => f.key === key);
              alert(`Select at least one option for "${{fieldDef ? fieldDef.label : key}}".`);
              return null;
            }}
            arrays.push(vals.map(v => ({{ key, v }})));
          }}
          return cartesianProduct(arrays).map(combo => {{
            const cfg = {{ type: configType, ...fixedVals }};
            for (const {{ key, v }} of combo) cfg[key] = v;
            return cfg;
          }});
        }} else {{
          if (cbKeys.length === 1) {{
            const key = cbKeys[0];
            const vals = (fieldValues[key] || {{}}).value || [];
            if (!vals.length) {{
              const fieldDef = schema.fields.find(f => f.key === key);
              alert(`Select at least one option for "${{fieldDef ? fieldDef.label : key}}".`);
              return null;
            }}
            return vals.map(v => {{
              const cfg = {{ type: configType, ...fixedVals }};
              cfg[key] = v;
              return cfg;
            }});
          }}
          const cfg = {{ type: configType, ...fixedVals }};
          for (const key of cbKeys) {{
            cfg[key] = (fieldValues[key] || {{}}).value || [];
          }}
          return [cfg];
        }}
      }}

      function configLabel(cfg, schema) {{
        return schema.fields
          .map(f => {{
            const v = cfg[f.key];
            if (v === undefined || v === null) return '';
            if (Array.isArray(v)) return v.join('+');
            if (typeof v === 'object') return JSON.stringify(v);
            return String(v);
          }})
          .filter(Boolean)
          .join(' / ');
      }}

      // These slugs feed the generated experiment name, which in turn becomes an SSH
      // ControlPath component on the remote hosts (mhbench-ssh/<experiment_name>/<hash>)
      // - AF_UNIX socket paths are capped at 108 bytes, so a long name silently breaks
      // every SSH connection. Rather than blindly truncating (illegible, and doesn't
      // stop the underlying field values - e.g. LLM model slugs - from being long),
      // each plugin declares a short, legible nickname per option via the field's
      // `short_names` map (see ui_schema.py). Free-form fields (model names, script
      // paths - field types with no fixed set of "classes" to nickname) are left out
      // of the slug entirely rather than truncated. The final slice is just a safety
      // net for anything that slips through uncatalogued.
      function configSlug(cfg, schema) {{
        const fieldByKey = {{}};
        for (const f of (schema ? schema.fields : [])) fieldByKey[f.key] = f;
        const parts = Object.entries(cfg)
          .filter(([k]) => k !== 'type')
          .map(([k, v]) => {{
            const field = fieldByKey[k];
            const fieldType = field ? field.field_type : null;
            if (fieldType === 'text_with_suggestions' || fieldType === 'grouped_checkboxes' || fieldType === 'json') {{
              return null;  // free-form / unbounded - not a named "class", leave out of the slug
            }}
            if (fieldType === 'flat_checkboxes' && field.short_names && field.short_names[v]) {{
              return field.short_names[v];
            }}
            if (fieldType === 'key_value_pairs' && v && typeof v === 'object') {{
              const shortKeys = field.key_short_names || {{}};
              return Object.entries(v).map(([ek, ev]) => (shortKeys[ek] || ek) + ev).join('');
            }}
            return typeof v === 'string' ? v : JSON.stringify(v);
          }})
          .filter(Boolean);
        const base = parts.length ? parts.join('_') : (schema ? schema.config_type : 'cfg');
        return base.toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 24);
      }}

      // Turn a backend error body into a readable line. FastAPI validation errors
      // put an array of {{loc,msg}} objects in `detail`, which would otherwise
      // stringify to "[object Object]".
      function formatSubmitError(data) {{
        if (!data) return 'unknown error';
        const d = data.detail;
        if (typeof d === 'string') return d;
        if (Array.isArray(d)) return d.map(x => {{
          const loc = Array.isArray(x.loc) ? x.loc.filter(p => p !== 'body').join('.') : '';
          return (loc ? loc + ': ' : '') + (x.msg || JSON.stringify(x));
        }}).join('; ');
        if (d) return JSON.stringify(d);
        return JSON.stringify(data);
      }}

      // Turn a backend error body into a readable line. FastAPI validation errors
      // put an array of {{loc,msg}} objects in `detail`, which would otherwise
      // stringify to "[object Object]".
      function formatSubmitError(data) {{
        if (!data) return 'unknown error';
        const d = data.detail;
        if (typeof d === 'string') return d;
        if (Array.isArray(d)) return d.map(x => {{
          const loc = Array.isArray(x.loc) ? x.loc.filter(p => p !== 'body').join('.') : '';
          return (loc ? loc + ': ' : '') + (x.msg || JSON.stringify(x));
        }}).join('; ');
        if (d) return JSON.stringify(d);
        return JSON.stringify(data);
      }}

      // ── Attacker list ─────────────────────────────────────────────────────
      const attackerList = [];

      function renderAtkChips() {{
        const chips = document.getElementById('atk-chips');
        const empty = document.getElementById('atk-chips-empty');
        const count = document.getElementById('atk-count');
        chips.innerHTML = '';
        if (attackerList.length === 0) {{ empty.style.display = ''; }}
        else {{
          empty.style.display = 'none';
          attackerList.forEach((item, idx) => {{
            const chip = document.createElement('div');
            chip.className = 'config-chip';
            chip.innerHTML = `<span class="config-chip-label" title="${{item.label}}">${{item.label}}</span>
              <button type="button" class="config-chip-remove" data-idx="${{idx}}">✕</button>`;
            chips.appendChild(chip);
          }});
        }}
        count.textContent = attackerList.length ? ` (${{attackerList.length}})` : '';
      }}

      document.getElementById('atk-chips').addEventListener('click', e => {{
        const btn = e.target.closest('.config-chip-remove');
        if (!btn) return;
        attackerList.splice(parseInt(btn.dataset.idx), 1);
        renderAtkChips();
      }});

      const atkTypeSelect = document.getElementById('attacker-type');
      buildTypeDropdown(atkTypeSelect, ATTACKER_SCHEMAS);
      atkTypeSelect.addEventListener('change', function() {{
        renderFields(document.getElementById('atk-fields-container'), ATTACKER_SCHEMAS[this.value]);
      }});
      atkTypeSelect.dispatchEvent(new Event('change'));

      document.getElementById('atk-add-btn').addEventListener('click', () => {{
        const configType = atkTypeSelect.value;
        const schema = ATTACKER_SCHEMAS[configType];
        if (!schema) return;
        const fieldValues = readFieldValues(document.getElementById('atk-fields-container'));
        const configs = buildConfigs(configType, schema, fieldValues);
        if (!configs) return;
        for (const cfg of configs) {{
          attackerList.push({{ config: cfg, label: configLabel(cfg, schema), slug: configSlug(cfg, schema) }});
        }}
        renderAtkChips();
      }});

      // ── Defender list ─────────────────────────────────────────────────────
      const defenderList = [];

      function renderDefChips() {{
        const chips = document.getElementById('def-chips');
        const empty = document.getElementById('def-chips-empty');
        const count = document.getElementById('def-count');
        chips.innerHTML = '';
        if (defenderList.length === 0) {{ empty.style.display = ''; }}
        else {{
          empty.style.display = 'none';
          defenderList.forEach((item, idx) => {{
            const chip = document.createElement('div');
            chip.className = 'config-chip';
            chip.innerHTML = `<span class="config-chip-label" title="${{item.label}}">${{item.label}}</span>
              <button type="button" class="config-chip-remove" data-idx="${{idx}}">✕</button>`;
            chips.appendChild(chip);
          }});
        }}
        count.textContent = defenderList.length ? ` (${{defenderList.length}})` : '';
      }}

      document.getElementById('def-chips').addEventListener('click', e => {{
        const btn = e.target.closest('.config-chip-remove');
        if (!btn) return;
        defenderList.splice(parseInt(btn.dataset.idx), 1);
        renderDefChips();
      }});

      const defTypeSelect = document.getElementById('defender-type');
      buildTypeDropdown(defTypeSelect, DEFENDER_SCHEMAS);
      defTypeSelect.addEventListener('change', function() {{
        renderFields(document.getElementById('def-fields-container'), DEFENDER_SCHEMAS[this.value]);
      }});
      defTypeSelect.dispatchEvent(new Event('change'));

      document.getElementById('def-add-none-btn').addEventListener('click', () => {{
        defenderList.push({{ config: null, label: '(no defender)', slug: 'nodef' }});
        renderDefChips();
      }});

      document.getElementById('def-add-btn').addEventListener('click', () => {{
        const configType = defTypeSelect.value;
        const schema = DEFENDER_SCHEMAS[configType];
        if (!schema) return;
        const fieldValues = readFieldValues(document.getElementById('def-fields-container'));
        const configs = buildConfigs(configType, schema, fieldValues);
        if (!configs) return;
        for (const cfg of configs) {{
          defenderList.push({{ config: cfg, label: configLabel(cfg, schema), slug: configSlug(cfg, schema) }});
        }}
        renderDefChips();
      }});

      // ── Form submit ───────────────────────────────────────────────────────
      document.getElementById('submit-form').addEventListener('submit', async function(e) {{
        e.preventDefault();
        const btn = document.getElementById('submit-btn');
        btn.disabled = true;
        const box = document.getElementById('results-box');
        box.innerHTML = '';
        box.classList.add('visible');

        const envs = [...selectedEnvs.keys()];
        if (envs.length === 0) {{
          box.innerHTML = '<span class="result-err">No environments selected.</span>';
          btn.disabled = false; return;
        }}
        if (attackerList.length === 0) {{
          box.innerHTML = '<span class="result-err">No attackers added.</span>';
          btn.disabled = false; return;
        }}
        if (defenderList.length === 0) {{
          box.innerHTML = '<span class="result-err">No defenders added (use "+ No defender" if you want none).</span>';
          btn.disabled = false; return;
        }}

        const repeats = parseInt(document.getElementById('repeats').value) || 1;
        const namePrefix = document.getElementById('name-prefix').value.trim();
        if (/\\s/.test(namePrefix)) {{
          box.innerHTML = '<span class="result-err">Name prefix cannot contain a space ' +
            '(MHBench builds SSH ControlPath strings from the experiment name unescaped - a ' +
            'space silently breaks every ansible/SSH step for that experiment). Use underscores ' +
            'or dashes instead, e.g. "test_defender" or "test-defender".</span>';
          btn.disabled = false; return;
        }}

        // MHBench builds SSH ControlPath as /tmp/mhbench-ssh/<experiment_name>/<40-char host
        // hash>, and AF_UNIX socket paths cap out at 108 bytes: 17 ("/tmp/mhbench-ssh/") + 1
        // ("/") + 40 (hash) = 58 fixed, leaving 50 for the name itself. Attacker/defender/env
        // slugs are already kept short via each plugin's `short_names` map (see configSlug) -
        // this catches the remaining variable: a name prefix (or combination) too long for
        // that budget, so it fails fast here instead of silently breaking SSH mid-run.
        const MAX_EXP_NAME_LEN = 50;
        let longestName = '';
        for (let i = 0; i < repeats; i++) {{
          for (const atkItem of attackerList) {{
            for (const defItem of defenderList) {{
              for (const envSpec of envs) {{
                const envStem = ENV_NICKNAMES[envSpec] || envSpec.split('/').pop();
                const parts = [namePrefix, atkItem.slug, defItem.slug, envStem, String(i)].filter(Boolean);
                const expName = parts.join('_');
                if (expName.length > longestName.length) longestName = expName;
              }}
            }}
          }}
        }}
        if (longestName.length > MAX_EXP_NAME_LEN) {{
          box.innerHTML = `<span class="result-err">Generated experiment name "${{longestName}}" is ` +
            `${{longestName.length}} chars, over the ${{MAX_EXP_NAME_LEN}}-char safe limit (MHBench's SSH ` +
            `ControlPath construction breaks silently past this). Use a shorter name prefix.</span>`;
          btn.disabled = false; return;
        }}

        const total = attackerList.length * defenderList.length * envs.length * repeats;
        box.innerHTML += `<span class="result-info">Submitting ${{total}} experiment(s) ` +
          `(${{attackerList.length}} attacker(s) × ${{defenderList.length}} defender(s) × ` +
          `${{envs.length}} env(s) × ${{repeats}} repeat(s))...</span>\n`;

        let ok = 0, err = 0;
        for (let i = 0; i < repeats; i++) {{
          for (const atkItem of attackerList) {{
            for (const defItem of defenderList) {{
              for (const envSpec of envs) {{
                const envStem = ENV_NICKNAMES[envSpec] || envSpec.split('/').pop();
                const parts = [namePrefix, atkItem.slug, defItem.slug, envStem, String(i)].filter(Boolean);
                const expName = parts.join('_');
                const payload = {{ experiment_name: expName, environment: envSpec,
                                   attacker: atkItem.config, defender: defItem.config, trial: i }};
                try {{
                  const resp = await fetch('/submit', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify(payload),
                  }});
                  const data = await resp.json();
                  if (resp.ok) {{
                    box.innerHTML += `<span class="result-ok">  OK  ${{expName}}</span>\n`;
                    ok++;
                  }} else {{
                    box.innerHTML += `<span class="result-err">  ERR ${{expName}} → ${{formatSubmitError(data)}}</span>\n`;
                    err++;
                  }}
                }} catch(ex) {{
                  box.innerHTML += `<span class="result-err">  ERR ${{expName}} → ${{ex.message}}</span>\n`;
                  err++;
                }}
                box.scrollTop = box.scrollHeight;
              }}
            }}
          }}
        }}
        box.innerHTML += `<span class="result-info">Done: ${{ok}} submitted, ${{err}} failed.</span>\n`;
        btn.disabled = false;
      }});
    }});
  </script>
</head>
<body>
  <header>
    <h1>🧪 Experiment Dashboard</h1>
    <div class="refresh-bar">
      <span class="dot"></span>
      <span class="meta">Live · last updated <span id="ts"></span> · refreshes every 5s</span>
    </div>
  </header>
  <div class="tabs">
    <div class="tab active" data-panel="panel-dashboard">Experiments</div>
    <div class="tab" data-panel="panel-submit">Submit</div>
    <div class="tab" data-panel="panel-usage">API Usage</div>
  </div>

  <!-- Dashboard tab -->
  <div id="panel-dashboard" class="tab-panel active">
    <div id="dashboard-root">{_inner_html(len(experiments), _summary_cards(status_counts(experiments)), _rows(experiments))}</div>
  </div>

  <!-- Submit tab -->
  <div id="panel-submit" class="tab-panel">
    <div class="submit-wrap">
      <form id="submit-form">

        <div class="form-section">
          <h2>Environments</h2>
          <div class="env-layout">
            <div class="env-picker">
              <div class="env-controls">
                <select id="env-group-select" style="background:#0f172a;border:1px solid #334155;
                  border-radius:6px;color:#e2e8f0;padding:0.3rem 0.6rem;font-size:0.85rem;">
                  {_env_group_options()}
                </select>
                <button type="button" class="btn-sm" id="env-select-all">Select all</button>
                <button type="button" class="btn-sm" id="env-clear">Clear</button>
              </div>
              <div id="env-panels">{_env_panels()}</div>
            </div>
            <div class="env-selected-panel">
              <h3>Selected<span id="env-selected-count"></span></h3>
              <div id="env-chips" class="env-chips"></div>
              <span id="env-chips-empty" class="env-empty-note">None selected</span>
            </div>
          </div>
        </div>

        <div class="form-section">
          <h2>Attackers</h2>
          <div class="config-layout">
            <div class="config-form">
              <div class="form-row">
                <div class="form-group">
                  <label>Type</label>
                  <select id="attacker-type"></select>
                </div>
              </div>
              <div id="atk-fields-container"></div>
              <button type="button" class="add-btn" id="atk-add-btn">+ Add attacker</button>
            </div>
            <div class="config-list-panel">
              <h3>Attackers<span id="atk-count"></span></h3>
              <div id="atk-chips" class="config-chips"></div>
              <span id="atk-chips-empty" class="env-empty-note">None added</span>
            </div>
          </div>
        </div>

        <div class="form-section">
          <h2>Defenders</h2>
          <div class="config-layout">
            <div class="config-form">
              <div class="form-row">
                <div class="form-group">
                  <label>Type</label>
                  <select id="defender-type"></select>
                </div>
              </div>
              <div id="def-fields-container"></div>
              <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:0.75rem;">
                <button type="button" class="add-btn" style="margin-top:0" id="def-add-btn">+ Add defender</button>
                <button type="button" class="add-btn" style="margin-top:0;background:#334155" id="def-add-none-btn">+ No defender</button>
              </div>
            </div>
            <div class="config-list-panel">
              <h3>Defenders<span id="def-count"></span></h3>
              <div id="def-chips" class="config-chips"></div>
              <span id="def-chips-empty" class="env-empty-note">None added</span>
            </div>
          </div>
        </div>

        <div class="form-section">
          <h2>Run options</h2>
          <div class="form-row">
            <div class="form-group" style="flex:0 0 140px">
              <label>Repeats</label>
              <input id="repeats" type="number" min="1" value="1">
            </div>
            <div class="form-group">
              <label>Name prefix (auto if blank)</label>
              <input id="name-prefix" placeholder="e.g. graphsearch">
            </div>
          </div>
        </div>

        <button type="submit" class="submit-btn" id="submit-btn">Submit experiments</button>
      </form>
      <div id="results-box" class="results-box"></div>
    </div>
  </div>

  <!-- API Usage tab -->
  <div id="panel-usage" class="tab-panel">
    <div class="usage-wrap">
      <div class="usage-updated">Last checked <span id="usage-ts">—</span> · refreshes every 30s</div>
      <div id="usage-root">Loading…</div>
    </div>
  </div>

  <!-- Log viewer: opened by clicking an experiment row -->
  <div id="log-viewer-overlay" class="log-viewer-overlay">
    <div class="log-viewer-modal">
      <div class="log-viewer-header">
        <span class="title"><span id="log-viewer-name"></span><span class="sub" id="log-viewer-file-name"></span></span>
        <div class="log-viewer-actions">
          <label class="log-viewer-refresh-label">
            <input type="checkbox" id="log-viewer-autorefresh"> Live (updates when the log changes)
          </label>
          <button type="button" class="log-viewer-close" id="log-viewer-close">✕ Close</button>
        </div>
      </div>
      <div class="log-viewer-body">
        <div class="log-viewer-files" id="log-viewer-files"></div>
        <pre class="log-viewer-content" id="log-viewer-content">Select a file on the left to view its contents.</pre>
      </div>
    </div>
  </div>
</body>
</html>"""


def _env_group_options() -> str:
    groups = load_environments()
    return "".join(f'<option value="{g}">{g}</option>' for g in groups)

def _env_panels():
    groups = load_environments()
    html = ""
    first = True
    for group, stems in groups.items():
        group_id = group.replace("-", "_")
        panel_class = "env-group-panel active" if first else "env-group-panel"
        first = False
        html += f'<div id="env-group-{group}" class="{panel_class}"><div class="env-grid">'
        for stem in stems:
            spec = stem if group == "misc" else f"{group}/{stem}"
            html += (f'<div class="env-item">'
                     f'<input type="checkbox" class="env-cb" id="env-{group_id}-{stem}"'
                     f' value="{spec}" data-label="{stem}">'
                     f'<label for="env-{group_id}-{stem}">{stem}</label>'
                     f'</div>')
        html += '</div></div>'
    return html

def _summary_cards(counts):
    cards = ""
    for status, (icon, color, bg) in STATUS_STYLE.items():
        n = counts.get(status, 0)
        cards += (f'<div class="summary-card" style="border-left:4px solid {color};background:{bg}">'
                  f'<div class="summary-count" style="color:{color}">{n}</div>'
                  f'<div class="summary-label" style="color:{color}">{icon} {status}</div></div>')
    return cards

def _rows(experiments):
    rows = ""
    for e in experiments:
        name = e.get("experiment_name", "—")
        status = e.get("status", "Queued")
        env = e.get("environment_spec", "—")
        attacker = (e.get("attacker") or {}).get("strategy", "—")
        updated = fmt_time(e.get("updated_at"))
        created = fmt_time(e.get("created_at"))
        retries = e.get("retry_count", 0)
        icon, color, bg = STATUS_STYLE.get(status, ("⬜", "#6b7280", "#f3f4f6"))
        badge = f'<span class="badge" style="background:{bg};color:{color};border:1px solid {color}">{icon} {status}</span>'
        retry_html = f' <span class="retry-badge">↩ {retries}</span>' if retries else ""
        err_html = _error_html(e)
        safe_name = html.escape(name, quote=True)
        rows += (f'<tr class="exp-row" data-name="{safe_name}" title="Click to browse this experiment\'s log files">'
                 f'<td class="name-cell">{name}</td><td>{badge}{retry_html}{err_html}</td>'
                 f'<td>{env}</td><td>{attacker}</td>'
                 f'<td class="time-cell">{created}</td><td class="time-cell">{updated}</td></tr>')
    return rows

# ── Experiment log viewer: browse an experiment's output-dir files from the UI ──
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

def _inner_html(total, summary_cards, rows):
    return f"""
  <div class="summary">{summary_cards}</div>
  <div class="total">{total} experiments total</div>
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th>Name</th><th>Status</th><th>Environment</th><th>Attacker</th><th>Created</th><th>Updated</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


_SUBMITTED_SPECS_DIR = Path(__file__).resolve().parent / "submitted_specs"


def _attacker_to_plugin_spec(payload: dict) -> dict:
    """The manager's attacker config is a (plugin + spec-file) pair. The browser still builds the
    embedded {type, ...fields} form; convert it here (server-side, same host as the manager): write
    the bespoke fields to a spec file and pass attacker_plugin + attacker_spec (its path)."""
    atk = payload.get("attacker")
    if not (isinstance(atk, dict) and atk.get("type")):
        return payload
    plugin = atk["type"]
    spec = {k: v for k, v in atk.items() if k != "type"}  # bespoke fields only; manager injects type
    _SUBMITTED_SPECS_DIR.mkdir(parents=True, exist_ok=True)
    name = payload.get("experiment_name", "exp")
    spec_path = _SUBMITTED_SPECS_DIR / f"{name}_attacker.json"
    spec_path.write_text(json.dumps(spec, indent=2))
    out = {k: v for k, v in payload.items() if k != "attacker"}
    out["attacker_plugin"] = plugin
    out["attacker_spec"] = str(spec_path)
    return out


def proxy_submit(payload: dict) -> tuple[int, dict]:
    payload = _attacker_to_plugin_spec(payload)
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


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence request logs

    def _respond(self, code, content_type, body):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/":
            experiments = load_experiments()
            self._respond(200, "text/html; charset=utf-8", render_html(experiments))
        elif self.path == "/data":
            experiments = load_experiments()
            counts = status_counts(experiments)
            total = len(experiments)
            payload = json.dumps({"html": _inner_html(total, _summary_cards(counts), _rows(experiments))})
            self._respond(200, "application/json", payload)
        elif self.path == "/api_usage":
            payload = json.dumps({"html": _usage_html()})
            self._respond(200, "application/json", payload)
        elif self.path.startswith("/experiment_files?"):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            name = (qs.get("name") or [""])[0]
            files = list_experiment_files(name)
            self._respond(200, "application/json", json.dumps({"files": files}))
        elif self.path.startswith("/experiment_file_wait?"):
            # Long-polls until the file changes (or times out) so the client can "refresh on
            # change" instead of re-fetching on a blind timer. Safe to block this thread -
            # the server is threading (see __main__) so other requests aren't stalled by it.
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            name = (qs.get("name") or [""])[0]
            rel_path = (qs.get("path") or [""])[0]
            since_size = (qs.get("since_size") or [None])[0]
            since_mtime = (qs.get("since_mtime") or [None])[0]
            result = wait_for_experiment_file_change(name, rel_path, since_size, since_mtime)
            self._respond(200, "application/json", json.dumps(result))
        elif self.path.startswith("/experiment_file?"):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            name = (qs.get("name") or [""])[0]
            rel_path = (qs.get("path") or [""])[0]
            ok, content = read_experiment_file(name, rel_path)
            if ok:
                size, mtime = _stat_experiment_file(name, rel_path) or (None, None)
                self._respond(200, "application/json", json.dumps({"content": content, "size": size, "mtime": mtime}))
            else:
                self._respond(404, "application/json", json.dumps({"error": content}))
        else:
            self._respond(404, "text/plain", "Not found")

    def do_POST(self):
        if self.path == "/submit":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                payload = json.loads(body)
            except Exception:
                self._respond(400, "application/json", json.dumps({"detail": "Invalid JSON"}))
                return
            status, result = proxy_submit(payload)
            self._respond(status, "application/json", json.dumps(result))
        else:
            self._respond(404, "text/plain", "Not found")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Experiment dashboard server")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    ThreadingHTTPServer.allow_reuse_address = True
    # Threading matters here specifically because of /experiment_file_wait: it long-polls
    # (blocks for up to _LOG_WAIT_TIMEOUT_S seconds inside the request) so the main table's
    # own 5s auto-refresh - and every other viewer's log tail - would stall behind it on a
    # single-threaded HTTPServer.
    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"Dashboard running at http://localhost:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
