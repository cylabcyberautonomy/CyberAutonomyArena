#!/usr/bin/env python3
"""Experiment dashboard — reads experiment_registry.yaml and serves a live HTML UI."""

import argparse
import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import yaml

EST = timezone(timedelta(hours=-5))

CONFIG_PATH = Path(__file__).parent / "config.yaml"
EXPERIMENT_SERVER = "http://localhost:8000/experiments"

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

REGISTRY_PATH = Path(__file__).parent / "experiment_registry.yaml"

STATUS_STYLE = {
    "Queued":    ("⬜", "#6b7280", "#f3f4f6"),
    "Deploying": ("🔵", "#2563eb", "#dbeafe"),
    "Running":   ("🟡", "#d97706", "#fef3c7"),
    "Error":     ("🔴", "#dc2626", "#fee2e2"),
    "Finished":  ("✅", "#059669", "#d1fae5"),
}

def load_experiments():
    if not REGISTRY_PATH.exists():
        return []
    with open(REGISTRY_PATH) as f:
        data = yaml.safe_load(f) or {}

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

    experiments = data.get("experiments", [])
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

def status_counts(experiments):
    counts = {s: 0 for s in STATUS_STYLE}
    for e in experiments:
        s = e.get("status", "Queued")
        counts[s] = counts.get(s, 0) + 1
    return counts

def _plugin_schemas_js() -> str:
    atk_json = json.dumps(_ATTACKER_SCHEMAS, indent=2)
    def_json = json.dumps(_DEFENDER_SCHEMAS, indent=2)
    return f"  <script>\n    const ATTACKER_SCHEMAS = {atk_json};\n    const DEFENDER_SCHEMAS = {def_json};\n  </script>"

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
        rows += f"""
        <tr>
          <td class="name-cell">{name}</td>
          <td>{badge}{retry_html}</td>
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
    .refresh-bar {{ display: flex; align-items: center; gap: 0.5rem; }}
    .dot {{ width: 8px; height: 8px; border-radius: 50%; background: #22c55e;
            animation: pulse 2s infinite; display: inline-block; }}
    @keyframes pulse {{ 0%,100%{{opacity:1}} 50%{{opacity:0.3}} }}
    .total {{ color: #94a3b8; font-size: 0.8rem; padding: 0 2rem 0.5rem;}}

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
      }}

      function readFieldValues(containerEl) {{
        const result = {{}};
        containerEl.querySelectorAll('input[data-field-key]').forEach(input => {{
          result[input.dataset.fieldKey] = {{ type: input.dataset.fieldType, value: input.value.trim() }};
        }});
        containerEl.querySelectorAll('[data-field-type="flat_checkboxes"],[data-field-type="grouped_checkboxes"]').forEach(grid => {{
          result[grid.dataset.fieldKey] = {{
            type: grid.dataset.fieldType,
            value: [...grid.querySelectorAll('.llm-cb:checked')].map(cb => cb.value),
          }};
        }});
        containerEl.querySelectorAll('[data-field-type="key_value_pairs"]').forEach(grid => {{
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
        const cbKeys   = schema.fields.filter(f => f.field_type === 'flat_checkboxes' || f.field_type === 'grouped_checkboxes').map(f => f.key);
        const textKeys = schema.fields.filter(f => f.field_type === 'text_with_suggestions' || f.field_type === 'json').map(f => f.key);
        const kvKeys   = schema.fields.filter(f => f.field_type === 'key_value_pairs').map(f => f.key);

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

      function configSlug(cfg) {{
        return Object.entries(cfg)
          .filter(([k]) => k !== 'type')
          .map(([, v]) => (typeof v === 'string' ? v : JSON.stringify(v)))
          .join('_')
          .toLowerCase()
          .replace(/[^a-z0-9]/g, '')
          .slice(0, 32);
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
          attackerList.push({{ config: cfg, label: configLabel(cfg, schema), slug: configSlug(cfg) }});
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
          defenderList.push({{ config: cfg, label: configLabel(cfg, schema), slug: configSlug(cfg) }});
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
        const total = attackerList.length * defenderList.length * envs.length * repeats;
        box.innerHTML += `<span class="result-info">Submitting ${{total}} experiment(s) ` +
          `(${{attackerList.length}} attacker(s) × ${{defenderList.length}} defender(s) × ` +
          `${{envs.length}} env(s) × ${{repeats}} repeat(s))...</span>\n`;

        let ok = 0, err = 0;
        for (let i = 0; i < repeats; i++) {{
          for (const atkItem of attackerList) {{
            for (const defItem of defenderList) {{
              for (const envSpec of envs) {{
                const envStem = envSpec.split('/').pop();
                const parts = [namePrefix, atkItem.slug, defItem.slug, envStem, String(i)].filter(Boolean);
                const expName = parts.join('_');
                const payload = {{ experiment_name: expName, environment: envSpec,
                                   attacker: atkItem.config, defender: defItem.config }};
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
                    box.innerHTML += `<span class="result-err">  ERR ${{expName}} → ${{data.detail || JSON.stringify(data)}}</span>\n`;
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
        rows += (f'<tr><td class="name-cell">{name}</td><td>{badge}{retry_html}</td>'
                 f'<td>{env}</td><td>{attacker}</td>'
                 f'<td class="time-cell">{created}</td><td class="time-cell">{updated}</td></tr>')
    return rows

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


def proxy_submit(payload: dict) -> tuple[int, dict]:
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
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    args = parser.parse_args()
    REGISTRY_PATH = args.registry

    HTTPServer.allow_reuse_address = True
    server = HTTPServer(("0.0.0.0", args.port), Handler)
    print(f"Dashboard running at http://localhost:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
