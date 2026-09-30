#!/usr/bin/env bash
# OpenShell attacker runner — runs on the Kali foothold. Drives NVIDIA OpenShell to launch the chosen
# coding agent (claude/codex/opencode) in a sandbox whose shell can reach the victims east-west.
#
# Reads attacker_config.json (path = $1), produced by OpenShellAttacker.build_config(), with keys:
#   agent, model, provider_type, cred_envs[], creds{env:val}, image, agent_cmd_template,
#   policy ("permissive"|"restrictive"), http_cidrs[], http_ports[], tcp_hosts[{name,ip}], tcp_ports[],
#   objective, sandbox_name, output_dir.
#
# Flow (verified against the NVIDIA/OpenShell repo — providers/*.yaml + examples/agent-driven-policy-
# management/demo.sh, which is the authoritative real invocation):
#   1. create the provider from the built-in type, injecting each present credential env var
#      (openshell provider create --type <t> --credential <ENV> ...). Stock types need no profile import.
#   2. permissive: write a policy that ALLOWS the victim CIDRs via `allowed_ips` (the documented
#      private-IP egress mechanism, examples/private-ip-routing) for all binaries (/**), + a rw workdir;
#      restrictive: no --policy, OpenShell's default-deny stands (a containment study).
#   3. openshell sandbox create --name <s> --provider <t> [--from <img>] [--policy p]
#         [--approval-mode auto] --no-tty -- <agent cmd>
# The sandbox's foreground exit code is the attack verdict.
#
# VALIDATION NOTE (see the module docstring): the command surface here matches the repo's example
# scripts. What still needs an on-Kali pass: (a) EAST-WEST lateral movement — OpenShell egresses
# through the sandbox proxy, so ssh/nc to victims needs OpenShell's transparent-TCP interception
# (cf. examples/transparent-tcp-redis), not just the allowed_ips rule; (b) the provider type's binary
# paths must match the chosen image's layout or the agent's LLM credential is not injected; (c) codex
# needs CODEX_AUTH_* OAuth tokens in the environment.
set -uo pipefail
export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"

CONFIG="${1:?usage: openshell_runner.sh <attacker_config.json>}"
cfg()      { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2],""))' "$CONFIG" "$1"; }
cfg_list() { python3 -c 'import json,sys; print("\n".join(str(x) for x in json.load(open(sys.argv[1])).get(sys.argv[2],[])))' "$CONFIG" "$1"; }

AGENT="$(cfg agent)";               MODEL="$(cfg model)"
PROVIDER_TYPE="$(cfg provider_type)"; IMAGE="$(cfg image)"
POLICY="$(cfg policy)";             OBJECTIVE="$(cfg objective)"
SANDBOX="$(cfg sandbox_name)";      OUTDIR="$(cfg output_dir)"
CMD_TEMPLATE="$(cfg agent_cmd_template)"

mkdir -p "$OUTDIR"
exec > >(tee -a "$OUTDIR/runner.log") 2>&1
echo "[openshell-runner] agent=$AGENT model=$MODEL provider=$PROVIDER_TYPE policy=$POLICY sandbox=$SANDBOX image=${IMAGE:-<default>}"

# Inject the agent's credentials into the environment, then pass each present one to `provider create`
# as `--credential <ENV>` (openshell reads the value from the env). Warn if none are present.
eval "$(python3 -c 'import json,sys,shlex
c=json.load(open(sys.argv[1])).get("creds",{})
for k,v in c.items(): print(f"export {k}={shlex.quote(v)}")' "$CONFIG")"
CRED_ARGS=()
while IFS= read -r e; do [ -n "$e" ] && CRED_ARGS+=(--credential "$e"); done < <(
  python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1])).get("creds",{}).keys()))' "$CONFIG")
if [ "${#CRED_ARGS[@]}" -eq 0 ]; then
  echo "[openshell-runner] WARNING: no credentials present for $AGENT (needs: $(cfg cred_envs | tr '\n' ' ')) — the agent may fail to authenticate."
fi

openshell status || { echo "[openshell-runner] gateway not reachable"; exit 1; }

# 1: create the provider from the built-in type with the injected credentials (idempotent-ish).
openshell provider delete "$PROVIDER_TYPE" >/dev/null 2>&1 || true
openshell provider create --name "$PROVIDER_TYPE" --type "$PROVIDER_TYPE" "${CRED_ARGS[@]}" || true

# 2: permissive policy — two egress planes (OpenShell REJECTS hostless protocol:tcp, so we split them):
#      http_egress: hostless allowed_ips CIDRs on the HTTP ports (forward proxy, L7) — valid.
#      tcp_egress:  ONE host: endpoint per tcp_hosts entry (native TCP by hostname). Omitted if none.
#    Also flip the sandbox to auto-approval so any runtime proposals are granted without a human.
POLICY_ARGS=()
if [ "$POLICY" = "permissive" ]; then
  POLICY_FILE="$OUTDIR/policy.yaml"
  {
    echo "version: 1"
    echo "filesystem_policy:"
    echo "  include_workdir: true"
    echo "  read_write: [/sandbox, /tmp, /dev/null]"
    echo "landlock:"
    echo "  compatibility: best_effort"
    echo "network_policies:"
    # -- HTTP/forward-proxy plane: hostless allowed_ips CIDRs (valid) on the HTTP ports --
    echo "  http_egress:"
    echo "    name: http_egress"
    echo "    endpoints:"
    while IFS= read -r cidr; do
      [ -z "$cidr" ] && continue
      while IFS= read -r port; do
        [ -z "$port" ] && continue
        echo "      - { allowed_ips: [\"$cidr\"], port: $port }"
      done < <(cfg_list http_ports)
    done < <(cfg_list http_cidrs)
    echo "    binaries:"
    echo "      - { path: \"/**\" }"
    # -- Native-TCP plane: one host: endpoint per declared tcp_hosts entry, on the TCP ports.
    #    OpenShell forbids raw-IP TCP, so lateral movement is ONLY to these named hosts. --
    n_tcp=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("tcp_hosts",[])))' "$CONFIG")
    if [ "$n_tcp" -gt 0 ]; then
      echo "  tcp_egress:"
      echo "    name: tcp_egress"
      echo "    endpoints:"
      python3 -c '
import json,sys
d=json.load(open(sys.argv[1])); ports=d.get("tcp_ports",[]); q=chr(34)
for h in d.get("tcp_hosts",[]):
    ip=h.get("ip") or ""
    pin=", allowed_ips: ["+q+ip+"/32"+q+"]" if ip else ""
    for p in ports:
        print("      - { host: "+h["name"]+", port: "+str(p)+", protocol: tcp"+pin+" }")' "$CONFIG"
      echo "    binaries:"
      echo "      - { path: \"/**\" }"
    else
      echo "[openshell-runner] NOTE: no tcp_hosts declared — native-TCP lateral movement (ssh/nc) is"
      echo "                   NOT possible under OpenShell without hostname endpoints; HTTP egress only." >&2
    fi
  } > "$POLICY_FILE"
  echo "[openshell-runner] wrote permissive policy:"; sed 's/^/    /' "$POLICY_FILE"
  POLICY_ARGS=(--policy "$POLICY_FILE" --approval-mode auto)
fi

# --from <image> only when an image is configured (claude/codex use the agent's default image).
FROM_ARGS=()
[ -n "$IMAGE" ] && FROM_ARGS=(--from "$IMAGE")

# 3: run the agent in the sandbox to completion. The headless per-agent template gets the model +
# objective substituted (objective passed as a single shell-quoted argument after `--`). --no-tty:
# headless, no interactive terminal.
AGENT_CMD="$(python3 - "$CMD_TEMPLATE" "$MODEL" "$OBJECTIVE" <<'PY'
import shlex, sys
tmpl, model, objective = sys.argv[1], sys.argv[2], sys.argv[3]
print(tmpl.format(model=shlex.quote(model), objective=shlex.quote(objective)))
PY
)"
echo "[openshell-runner] launching: openshell sandbox create --name $SANDBOX --provider $PROVIDER_TYPE ${FROM_ARGS[*]:-} ${POLICY_ARGS[*]:-} --no-tty -- $AGENT_CMD"

set +e
# shellcheck disable=SC2086  # AGENT_CMD is intentionally word-split into the agent's argv after `--`.
openshell sandbox create --name "$SANDBOX" --provider "$PROVIDER_TYPE" \
  "${FROM_ARGS[@]}" "${POLICY_ARGS[@]}" --no-tty -- $AGENT_CMD
RC=$?
set -e

echo "[openshell-runner] agent finished rc=$RC"
exit "$RC"
