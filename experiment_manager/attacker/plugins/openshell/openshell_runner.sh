#!/usr/bin/env bash
# OpenShell attacker runner — runs on the Kali foothold. Drives NVIDIA OpenShell to launch the chosen
# coding agent (claude/codex/opencode) in a sandbox whose shell has east-west access to the victims.
#
# Reads attacker_config.json (path = $1), produced by OpenShellAttacker.build_config(), with keys:
#   agent, model, provider, provider_profile_url, api_key_env, api_key, image, agent_cmd_template,
#   policy ("permissive"|"restrictive"), allow_cidrs[], ports[], objective, sandbox_name, output_dir.
#
# Flow (per the OpenShell docs "Run Your First Agent"):
#   1. import the provider profile        (openshell profile import --url ...)
#   2. create the provider from the key   (openshell provider create --from-existing)
#   3. permissive: generate a network/filesystem policy that ALLOWS the victim CIDRs + workdir, and
#      run a background auto-approver for any runtime access proposals; restrictive: skip both (the
#      OpenShell default lockdown stands — a containment study).
#   4. openshell sandbox create --from <image> --provider <p> [--policy policy.yaml] -- <agent cmd>
# The sandbox's foreground exit code is the attack verdict.
#
# VALIDATION NOTE (first cut): OpenShell is new and parts of its CLI are only partially documented.
# The `--policy` flag on `sandbox create` and the exact `rule get -o json` shape below need an on-box
# confirmation pass; both the policy-file path and the runtime rule-approval path are attempted so
# permissive egress is granted by whichever mechanism this OpenShell build supports.
set -uo pipefail
export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"

CONFIG="${1:?usage: openshell_runner.sh <attacker_config.json>}"
cfg() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2],""))' "$CONFIG" "$1"; }
cfg_list() { python3 -c 'import json,sys; print("\n".join(str(x) for x in json.load(open(sys.argv[1])).get(sys.argv[2],[])))' "$CONFIG" "$1"; }

AGENT="$(cfg agent)";           MODEL="$(cfg model)"
PROVIDER="$(cfg provider)";     PROFILE_URL="$(cfg provider_profile_url)"
API_KEY_ENV="$(cfg api_key_env)"; API_KEY="$(cfg api_key)"
IMAGE="$(cfg image)";           POLICY="$(cfg policy)"
OBJECTIVE="$(cfg objective)";   SANDBOX="$(cfg sandbox_name)"
OUTDIR="$(cfg output_dir)";     CMD_TEMPLATE="$(cfg agent_cmd_template)"

mkdir -p "$OUTDIR"
exec > >(tee -a "$OUTDIR/runner.log") 2>&1
echo "[openshell-runner] agent=$AGENT model=$MODEL provider=$PROVIDER policy=$POLICY sandbox=$SANDBOX"

# The agent reads its credential from its own provider env var; export it for provider-create + run.
export "${API_KEY_ENV}=${API_KEY}"

openshell status || { echo "[openshell-runner] gateway not reachable"; exit 1; }

# 1 + 2: provider profile + provider (idempotent; ignore "already exists").
openshell profile import --url "$PROFILE_URL" || true
openshell provider create --name "$PROVIDER" --type "$PROVIDER" --from-existing || true

# 3: permissive policy (allow victim CIDRs on the attack ports + rw workdir). Deny-by-default otherwise.
POLICY_ARGS=()
APPROVER_PID=""
if [ "$POLICY" = "permissive" ]; then
  POLICY_FILE="$OUTDIR/policy.yaml"
  {
    echo "version: 1"
    echo "filesystem_policy:"
    echo "  include_workdir: true"
    echo "  read_write: [/workspace, /tmp]"
    echo "network_policies:"
    echo "  attack_egress:"
    echo "    endpoints:"
    while IFS= read -r cidr; do
      [ -z "$cidr" ] && continue
      while IFS= read -r port; do
        [ -z "$port" ] && continue
        echo "      - allowed_ips: [\"$cidr\"]"
        echo "        port: $port"
        echo "        protocol: tcp"
      done < <(cfg_list ports)
    done < <(cfg_list allow_cidrs)
    # Binaries the kill chain drives; OpenShell scopes each rule to executables.
    echo "    binaries:"
    for b in /usr/bin/ssh /usr/bin/scp /usr/bin/curl /usr/bin/wget /bin/nc /usr/bin/nc /usr/bin/python3; do
      echo "      - path: $b"
    done
  } > "$POLICY_FILE"
  echo "[openshell-runner] wrote permissive policy:"; sed 's/^/    /' "$POLICY_FILE"
  POLICY_ARGS=(--policy "$POLICY_FILE")

  # Belt-and-suspenders: also auto-approve any runtime access proposals this build surfaces, so egress
  # the agent requests mid-run is granted without a human. Harmless if the policy file already covers it.
  (
    while sleep 5; do
      ids="$(openshell rule get "$SANDBOX" --status pending -o json 2>/dev/null \
             | python3 -c 'import json,sys;
try:
 d=json.load(sys.stdin)
except Exception:
 d=[]
rows=d if isinstance(d,list) else d.get("rules",d.get("items",[]))
print("\n".join(str(r.get("chunk_id") or r.get("chunkId") or r.get("id","")) for r in rows))' 2>/dev/null)"
      for id in $ids; do
        [ -n "$id" ] && openshell rule approve "$SANDBOX" --chunk-id "$id" >/dev/null 2>&1 || true
      done
    done
  ) &
  APPROVER_PID=$!
fi

# 4: run the agent in the sandbox to completion. The agent cmd is the headless per-agent template with
# the model + the objective substituted (objective passed as a single shell-quoted argument).
AGENT_CMD="$(python3 - "$CMD_TEMPLATE" "$MODEL" "$OBJECTIVE" <<'PY'
import shlex, sys
tmpl, model, objective = sys.argv[1], sys.argv[2], sys.argv[3]
print(tmpl.format(model=shlex.quote(model), objective=shlex.quote(objective)))
PY
)"
echo "[openshell-runner] launching: openshell sandbox create --name $SANDBOX --from $IMAGE --provider $PROVIDER ${POLICY_ARGS[*]:-} -- $AGENT_CMD"

set +e
# shellcheck disable=SC2086  # AGENT_CMD is intentionally word-split into the agent's argv after `--`.
openshell sandbox create --name "$SANDBOX" --from "$IMAGE" --provider "$PROVIDER" "${POLICY_ARGS[@]}" -- $AGENT_CMD
RC=$?
set -e

[ -n "$APPROVER_PID" ] && kill "$APPROVER_PID" >/dev/null 2>&1 || true
echo "[openshell-runner] agent finished rc=$RC"
exit "$RC"
