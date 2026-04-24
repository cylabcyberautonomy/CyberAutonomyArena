#!/usr/bin/env python3
"""Experiment dashboard — reads experiment_registry.yaml and serves a live HTML UI."""

import argparse
import json
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import yaml

EST = timezone(timedelta(hours=-5))

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
    return data.get("experiments", [])

def status_counts(experiments):
    counts = {s: 0 for s in STATUS_STYLE}
    for e in experiments:
        s = e.get("status", "Queued")
        counts[s] = counts.get(s, 0) + 1
    return counts

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
  </style>
  <script>
    function autoRefresh() {{
      fetch('/data')
        .then(r => r.json())
        .then(data => {{
          document.getElementById('root').innerHTML = data.html;
          document.getElementById('ts').textContent = new Date().toLocaleTimeString();
        }});
    }}
    setInterval(autoRefresh, 5000);
    document.addEventListener('DOMContentLoaded', () => {{
      document.getElementById('ts').textContent = new Date().toLocaleTimeString();
    }});
  </script>
</head>
<body>
  <div id="root">{_inner_html(total, summary_cards, rows)}</div>
</body>
</html>"""

def _inner_html(total, summary_cards, rows):
    return f"""
  <header>
    <h1>🧪 Experiment Dashboard</h1>
    <div class="refresh-bar">
      <span class="dot"></span>
      <span class="meta">Live · last updated <span id="ts"></span> · refreshes every 5s</span>
    </div>
  </header>
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
            summary_cards = ""
            for status, (icon, color, bg) in STATUS_STYLE.items():
                n = counts.get(status, 0)
                summary_cards += f'<div class="summary-card" style="border-left:4px solid {color};background:{bg}"><div class="summary-count" style="color:{color}">{n}</div><div class="summary-label" style="color:{color}">{icon} {status}</div></div>'
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
                rows += f'<tr><td class="name-cell">{name}</td><td>{badge}{retry_html}</td><td>{env}</td><td>{attacker}</td><td class="time-cell">{created}</td><td class="time-cell">{updated}</td></tr>'
            payload = json.dumps({"html": _inner_html(total, summary_cards, rows)})
            self._respond(200, "application/json", payload)
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
