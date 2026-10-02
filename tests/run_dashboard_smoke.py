#!/usr/bin/env python3
"""
Self-contained integration smoke for the arena dashboard — NO cloud, NO real manager, NO credits.

The experiment smoke (run_experiment_smoke.py) drives a real manager end to end. This drives the
DASHBOARD end to end instead: it stands up a STUB upstream manager (captures whatever the dashboard
forwards) and the REAL dashboard server pointed at that stub, then exercises the dashboard's HTTP
surface and asserts:

  1. GET /             -> 200, serves the SPA shell with the submit form mount points.
  2. GET /api/schema   -> 200, the plugin ui-schemas are discovered (incalmo_strategy present).
  3. GET /api/experiments -> 200 (the dashboard proxies the manager's registry).
  4. POST /api/submit with the real BROWSER-shaped payload (bare-string environment + an EMBEDDED
     attacker {type,...}) -> the dashboard converts it server-side to the arena wire form and forwards
     THAT: environment becomes {environment_plugin, environment_spec=environments/<group>/<stem>.json},
     the attacker becomes attacker_plugin + attacker_spec (the bespoke fields as an inline dict, `type`
     stripped, no embedded `attacker`), and the embedded defender passes through unchanged.

It runs in ~1s and is safe to run anywhere (two loopback HTTP servers on ephemeral ports).

    PYTHONPATH=<repo> <venv>/bin/python tests/run_dashboard_smoke.py
    (e.g. PYTHONPATH=~/experiment_harness-arena ~/experiment_harness/.venv/bin/python ...)
"""
from __future__ import annotations

import json
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --------------------------------------------------------------------------- stub manager
_captured: list[dict] = []  # payloads the dashboard forwarded to "the manager"


class _StubManager(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        # the dashboard's /api/experiments proxies GET /experiments
        self._json(200, [])

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        _captured.append(body)
        self._json(201, {"experiment_name": body.get("experiment_name", "?"), "status": "Queued"})

    def _json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _http(method, url, body=None, timeout=10):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def _wait_up(url, tries=50):
    for _ in range(tries):
        try:
            _http("GET", url, timeout=1)
            return True
        except Exception:
            time.sleep(0.1)
    return False


def main() -> int:
    import dashboard  # import-safe: the server only starts under __main__

    stub_port = _free_port()
    dash_port = _free_port()

    stub = ThreadingHTTPServer(("127.0.0.1", stub_port), _StubManager)
    # point the dashboard at the stub instead of the real manager
    dashboard.EXPERIMENT_SERVER = f"http://127.0.0.1:{stub_port}/experiments"
    dash = ThreadingHTTPServer(("127.0.0.1", dash_port), dashboard.Handler)

    threading.Thread(target=stub.serve_forever, daemon=True).start()
    threading.Thread(target=dash.serve_forever, daemon=True).start()

    base = f"http://127.0.0.1:{dash_port}"
    rows: list[tuple[str, bool, str]] = []
    try:
        if not _wait_up(f"http://127.0.0.1:{stub_port}/experiments") or not _wait_up(f"{base}/"):
            print("FAIL: servers did not come up")
            return 1

        # 1. the SPA shell renders with the submit form mount points
        code, html = _http("GET", f"{base}/")
        ok = code == 200 and 'id="atk-type-select"' in html and 'id="submit-form"' in html
        rows.append(("GET / serves the SPA shell", ok, f"HTTP {code}, {len(html)} bytes"))

        # 2. the plugin ui-schemas are discovered and served
        code, body = _http("GET", f"{base}/api/schema")
        schema_ok = False
        try:
            schema = json.loads(body)
            schema_ok = code == 200 and "incalmo_strategy" in (schema.get("attacker") or {})
        except Exception:
            pass
        rows.append(("GET /api/schema discovers plugins", schema_ok,
                     f"HTTP {code}; attackers: {sorted((json.loads(body).get('attacker') or {})) if code==200 else '?'}"))

        # 3. the registry proxy works
        code, _ = _http("GET", f"{base}/api/experiments")
        rows.append(("GET /api/experiments proxies the manager", code == 200, f"HTTP {code}"))

        # 4. the browser-shaped payload is converted to the arena wire form server-side
        _captured.clear()
        payload = {
            "experiment_name": "dash_smoke",
            "environment": "instrumented/equifax_small_instrumented",   # bare <group>/<stem> (browser form)
            "attacker": {"type": "incalmo_strategy",                    # embedded attacker (browser form)
                         "strategy": "GraphSearch", "script_path": "/tmp/replay.json"},
            "defender": {"type": "canary"},
            "trial": 0,
        }
        code, _ = _http("POST", f"{base}/api/submit", payload)
        fwd = _captured[-1] if _captured else {}
        env = fwd.get("environment") if isinstance(fwd.get("environment"), dict) else {}
        env_ok = (env.get("environment_plugin") == "mhbench"
                  and env.get("environment_spec") == "environments/instrumented/equifax_small_instrumented.json")
        atk_ok = (fwd.get("attacker_plugin") == "incalmo_strategy"
                  and fwd.get("attacker_spec") == {"strategy": "GraphSearch", "script_path": "/tmp/replay.json"}
                  and "attacker" not in fwd)
        def_ok = fwd.get("defender") == {"type": "canary"}
        rows.append(("POST /api/submit -> environment wrapped + path-normalized", code == 201 and env_ok,
                     f"HTTP {code}; environment={env}"))
        rows.append(("POST /api/submit -> attacker plugin+spec (dict, type stripped)", atk_ok,
                     f"attacker_plugin={fwd.get('attacker_plugin')!r} attacker_spec={fwd.get('attacker_spec')!r}"))
        rows.append(("POST /api/submit -> embedded defender passes through", def_ok,
                     f"defender={fwd.get('defender')!r}"))
    finally:
        stub.shutdown()
        dash.shutdown()

    print("\nDASHBOARD SMOKE")
    for label, ok, detail in rows:
        print(f"  [{'OK ' if ok else '!! '}] {label}: {detail}")
    passed = all(ok for _, ok, _ in rows)
    print(f"\n{'PASS' if passed else 'FAIL'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
