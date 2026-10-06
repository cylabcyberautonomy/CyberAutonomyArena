"""OpenShell attacker runner — runs on the foothold, driving OpenShell to launch the coding agent in a sandbox."""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path


def _build_policy(cfg: dict) -> tuple[str, bool]:
    """Render the permissive policy YAML. Returns (yaml_text, has_tcp_plane)."""
    lines = [
        "version: 1",
        "filesystem_policy:",
        "  include_workdir: true",
        "  read_write: [/sandbox, /tmp, /dev/null]",
        "landlock:",
        "  compatibility: best_effort",
        "network_policies:",
        "  http_egress:",
        "    name: http_egress",
        "    endpoints:",
    ]
    for cidr in cfg.get("http_cidrs", []):
        for port in cfg.get("http_ports", []):
            lines.append(f'      - {{ allowed_ips: ["{cidr}"], port: {port} }}')
    lines += ["    binaries:", '      - { path: "/**" }']

    tcp_hosts = cfg.get("tcp_hosts", [])
    if tcp_hosts:
        lines += ["  tcp_egress:", "    name: tcp_egress", "    endpoints:"]
        for h in tcp_hosts:
            pin = f', allowed_ips: ["{h["ip"]}/32"]' if h.get("ip") else ""
            for port in cfg.get("tcp_ports", []):
                lines.append(f'      - {{ host: {h["name"]}, port: {port}, protocol: tcp{pin} }}')
        lines += ["    binaries:", '      - { path: "/**" }']
    return "\n".join(lines) + "\n", bool(tcp_hosts)


def main() -> int:
    cfg = json.loads(Path(sys.argv[1]).read_text())
    os.environ["PATH"] = os.path.expanduser("~/.local/bin") + ":/usr/local/bin:" + os.environ.get("PATH", "")
    out_dir = Path(cfg["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    log_file = open(out_dir / "runner.log", "a")

    def log(msg: str) -> None:
        print(msg, flush=True)
        log_file.write(msg + "\n")
        log_file.flush()

    def run(args: list[str], **kw) -> subprocess.CompletedProcess:
        log("[openshell-runner] $ " + " ".join(shlex.quote(a) for a in args))
        return subprocess.run(args, **kw)

    agent, provider = cfg["agent"], cfg["provider_type"]
    log(f"[openshell-runner] agent={agent} model={cfg['model']} provider={provider} "
        f"policy={cfg['policy']} sandbox={cfg['sandbox_name']} image={cfg['image'] or '<default>'}")

    creds = cfg.get("creds", {})
    for k, v in creds.items():
        os.environ[k] = v
    cred_args: list[str] = []
    for env_name in creds:
        cred_args += ["--credential", env_name]
    if not cred_args:
        log(f"[openshell-runner] WARNING: no credentials present for {agent} "
            f"(needs: {' '.join(cfg.get('cred_envs', []))}) — the agent may fail to authenticate.")

    if run(["openshell", "status"]).returncode != 0:
        log("[openshell-runner] gateway not reachable")
        return 1

    run(["openshell", "provider", "delete", provider],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run(["openshell", "provider", "create", "--name", provider, "--type", provider, *cred_args])

    policy_args: list[str] = []
    if cfg["policy"] == "permissive":
        policy_text, has_tcp = _build_policy(cfg)
        policy_file = out_dir / "policy.yaml"
        policy_file.write_text(policy_text)
        log("[openshell-runner] wrote permissive policy:\n    " + policy_text.replace("\n", "\n    "))
        if not has_tcp:
            log("[openshell-runner] NOTE: no tcp_hosts declared — native-TCP lateral movement (ssh/nc) "
                "is not possible under OpenShell without hostname endpoints; HTTP egress only.")
        policy_args = ["--policy", str(policy_file), "--approval-mode", "auto"]

    from_args = ["--from", cfg["image"]] if cfg["image"] else []

    agent_cmd = cfg["agent_cmd_template"].format(
        model=shlex.quote(cfg["model"]), objective=shlex.quote(cfg["objective"]))
    create = (["openshell", "sandbox", "create", "--name", cfg["sandbox_name"], "--provider", provider]
              + from_args + policy_args + ["--no-tty", "--"] + shlex.split(agent_cmd))
    rc = run(create).returncode
    log(f"[openshell-runner] agent finished rc={rc}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
