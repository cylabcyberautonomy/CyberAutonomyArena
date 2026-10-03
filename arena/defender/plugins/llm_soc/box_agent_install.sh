#!/usr/bin/env bash
# Box-side bootstrap for the defender box agent (the defender's in-environment effector).
#
# Runs ON the defender box (which, unlike the victims, has internet egress). Idempotent: skips the venv
# build if it already exists, and always (re)starts the agent. prepare_box_agent (harness side) has
# already rsynced the Defense repo to $DEF and placed the scoped key + box_agent_config.json.
#
# NOT YET LIVE-VALIDATED — mirrors box_es_install.sh, which took real live iteration to get right; expect
# the same here (venv/pip specifics, which Perry deps the actuators actually import on the box).
set -euo pipefail

DEF=/root/defense
VENV=/root/box_agent_venv

if [ ! -x "$VENV/bin/python" ]; then
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install --quiet --upgrade pip
    if [ -f "$DEF/requirements.txt" ]; then
        "$VENV/bin/pip" install --quiet -r "$DEF/requirements.txt"
    else
        # Fallback dep set the box agent's AnsibleExecutor + the host actuators import.
        "$VENV/bin/pip" install --quiet ansible-core ansible_runner elasticsearch pydantic rich faker
    fi
fi

# (re)start the agent: it listens on localhost:8900 on the box; the harness reaches it via the ssh -L
# tunnel prepare_box_agent opens (box is in-env, only reachable through the bastion).
pkill -f "defender.box_agent.agent" 2>/dev/null || true
sleep 1
cd "$DEF"
PYTHONPATH="$DEF" nohup "$VENV/bin/python" -m defender.box_agent.agent \
    --config /root/box_agent_config.json > /root/box_agent.log 2>&1 &
sleep 1
echo "box-agent started (pid $(pgrep -f 'defender.box_agent.agent' | head -1 || echo '?'))"
