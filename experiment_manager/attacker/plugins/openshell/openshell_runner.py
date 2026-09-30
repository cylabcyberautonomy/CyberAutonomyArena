"""OpenShell attacker runner — runs on the Kali foothold. Drives NVIDIA OpenShell to launch the chosen
coding agent (claude/codex/opencode) in a sandbox whose shell can reach the victims east-west.

Reads attacker_config.json (path = argv[1]), produced by OpenShellAttacker.build_config(), with keys:
    agent, model, provider_type, cred_envs[], creds{env:val}, image, agent_cmd_template,
    policy ("permissive"|"restrictive"), http_cidrs[], http_ports[], tcp_hosts[{name,ip}], tcp_ports[],
    objective, sandbox_name, output_dir.

Flow (verified against the NVIDIA/OpenShell repo — providers/*.yaml + examples/agent-driven-policy-
management/demo.sh, the authoritative real invocation):
  1. create the provider from the built-in type, injecting each present credential env var
     (openshell provider create --type <t> --credential <ENV> ...). Stock types need no profile import.
  2. permissive: write a policy with two egress planes — http_egress (hostless allowed_ips CIDRs on the
     HTTP ports, forward proxy) and tcp_egress (one host: endpoint per tcp_hosts, native TCP); restrictive:
     no --policy, so OpenShell's default-deny stands (a containment study).
  3. openshell sandbox create --name <s> --provider <t> [--from <img>] [--policy p] [--approval-mode auto]
     --no-tty -- <agent cmd>
The sandbox's foreground exit code is the attack verdict.

Stdlib only, run with the system python3 (OpenShell is a CLI, not a pip package — no venv).

VALIDATION NOTE (see the module docstring): the command surface matches the repo's example scripts.
What still needs an on-Kali pass: (a) OpenShell forbids raw-IP native TCP, so ssh/nc lateral movement
only reaches the hosts declared in tcp_hosts, by name; (b) the provider type's binary paths must match
the image layout or the agent's LLM credential is not injected; (c) codex needs CODEX_AUTH_* tokens.
"""
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
        # HTTP/forward-proxy plane: hostless allowed_ips CIDRs (valid) on the HTTP ports.
        "  http_egress:",
        "    name: http_egress",
        "    endpoints:",
    ]
    for cidr in cfg.get("http_cidrs", []):
        for port in cfg.get("http_ports", []):
            lines.append(f'      - {{ allowed_ips: ["{cidr}"], port: {port} }}')
    lines += ["    binaries:", '      - { path: "/**" }']

    # Native-TCP plane: one host: endpoint per declared tcp_hosts entry. OpenShell forbids raw-IP TCP,
    # so lateral movement is ONLY to these named hosts.
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

    # Inject the agent's credentials into the environment, then pass each present one to `provider
    # create` as --credential <ENV> (openshell reads the value from the env).
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

    # 1: create the provider from the built-in type with the injected credentials.
    run(["openshell", "provider", "delete", provider],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run(["openshell", "provider", "create", "--name", provider, "--type", provider, *cred_args])

    # 2: permissive policy + auto-approval; restrictive leaves OpenShell's default-deny in place.
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

    # --from <image> only when one is configured (claude/codex use the agent's default image).
    from_args = ["--from", cfg["image"]] if cfg["image"] else []

    # 3: run the agent in the sandbox to completion. The headless per-agent template gets the model +
    # objective substituted, then split into argv after `--`. --no-tty: headless, no interactive terminal.
    agent_cmd = cfg["agent_cmd_template"].format(
        model=shlex.quote(cfg["model"]), objective=shlex.quote(cfg["objective"]))
    create = (["openshell", "sandbox", "create", "--name", cfg["sandbox_name"], "--provider", provider]
              + from_args + policy_args + ["--no-tty", "--"] + shlex.split(agent_cmd))
    rc = run(create).returncode
    log(f"[openshell-runner] agent finished rc={rc}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
