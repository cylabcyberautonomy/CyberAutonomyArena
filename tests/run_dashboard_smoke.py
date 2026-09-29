#!/usr/bin/env python3
"""
Self-contained integration smoke for the arena dashboard — NO cloud, NO real manager, NO credits.

The experiment smoke (run_experiment_smoke.py) drives a real manager end to end. This drives the
DASHBOARD end to end instead: it stands up a STUB upstream manager (captures whatever the dashboard
forwards) and the REAL dashboard server pointed at that stub, then exercises the dashboard's HTTP
surface and asserts:

  1. GET /            -> 200, the submit UI renders (plugin ui-schemas loaded into the page).
  2. GET /data        -> 200 (the dashboard proxies the manager's registry).
  3. POST /submit with an EMBEDDED attacker payload -> the dashboard converts it to the
     (plugin + spec-file) pair form and forwards THAT to the manager: the captured payload has
     attacker_plugin + attacker_spec (no embedded `attacker`), and the spec file on disk holds the
     bespoke fields with `type` stripped.

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
from pathlib import Path


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
        # the dashboard's /data proxies GET /experiments
        self._json(200, [])

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        _captured.append(body)
        self._json(201, {"experiment_name": body.get("experiment_name", "?")})

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
            raw = r.read().decode()
            return r.status, raw
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
    written_spec: Path | None = None
    try:
        if not _wait_up(f"http://127.0.0.1:{stub_port}/experiments") or not _wait_up(f"{base}/"):
            print("FAIL: servers did not come up")
            return 1

        # 1. the page renders + the submit UI is present (schemas loaded)
        code, html = _http("GET", f"{base}/")
        ok = code == 200 and 'id="attacker-type"' in html and "incalmo_strategy" in html
        rows.append(("GET / renders submit UI (schemas loaded)", ok, f"HTTP {code}, {len(html)} bytes"))

        # 2. /data proxies the manager
        code, _ = _http("GET", f"{base}/data")
        rows.append(("GET /data proxies the manager", code == 200, f"HTTP {code}"))

        # 3. POST /submit converts embedded attacker -> (plugin + spec-file) pair form and forwards it
        _captured.clear()
        payload = {
            "experiment_name": "dash_smoke",
            "environment": "equifax_small",
            "attacker": {"type": "incalmo_strategy", "strategy": "GraphSearch", "c2_on_kali": True},
            "defender": {"type": "canary"},
            "trial": 0,
        }
        code, _ = _http("POST", f"{base}/submit", payload)
        fwd = _captured[-1] if _captured else {}
        conv_ok = (
            code == 201
            and fwd.get("attacker_plugin") == "incalmo_strategy"
            and isinstance(fwd.get("attacker_spec"), str)
            and "attacker" not in fwd
        )
        rows.append(("POST /submit converts to plugin+spec pair form", conv_ok,
                     f"HTTP {code}; forwarded keys: {sorted(fwd)}"))

        # the spec file the dashboard wrote holds the bespoke fields, `type` stripped
        spec_ok = False
        detail = "no attacker_spec forwarded"
        if isinstance(fwd.get("attacker_spec"), str):
            written_spec = Path(fwd["attacker_spec"])
            try:
                spec = json.loads(written_spec.read_text())
                spec_ok = spec == {"strategy": "GraphSearch", "c2_on_kali": True}
                detail = f"{written_spec.name}: {spec}"
            except Exception as e:
                detail = f"unreadable: {e}"
        rows.append(("spec file written (fields only, no type)", spec_ok, detail))
    finally:
        stub.shutdown()
        dash.shutdown()
        if written_spec is not None:
            try:
                written_spec.unlink(missing_ok=True)
            except Exception:
                pass

    print("\nDASHBOARD SMOKE")
    for label, ok, detail in rows:
        print(f"  [{'OK ' if ok else '!! '}] {label}: {detail}")
    passed = all(ok for _, ok, _ in rows)
    print(f"\n{'PASS' if passed else 'FAIL'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
