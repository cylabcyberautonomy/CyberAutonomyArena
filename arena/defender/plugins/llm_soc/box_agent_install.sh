#!/usr/bin/env bash
# Box-side bootstrap for the defender box agent (the defender's in-environment effector).
#
# Runs ON the defender box (Ubuntu 20.04 / py3.8, with internet egress — unlike the victims). The agent is
# SELF-CONTAINED: it imports no Perry Python (which needs py3.10+), only ansible_runner + the shipped
# `ansible/` YAML tree, so it runs fine on the box's py3.8 with ansible-core<2.14. prepare_box_agent
# (harness side) has already placed /root/box_agent_agent.py, /root/ansible/, /root/scoped_key and
# /root/box_agent_config.json. Idempotent: skips the venv build if present, always (re)starts the agent.
set -euo pipefail

VENV=/root/box_agent_venv

if [ ! -x "$VENV/bin/python" ]; then
    # Bare ubuntu_base (focal) lacks ensurepip/venv; the box has egress, so install from the mirror.
    if ! python3 -c "import ensurepip" >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq || true
        apt-get install -y -qq python3-venv python3-pip || true
    fi
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install --quiet --upgrade pip
    # ansible-core 2.14+ requires py3.9 as the control node; the box is py3.8, so pin <2.14 (it still
    # manages modern hosts). No Perry deps — the agent runs playbook YAMLs directly.
    "$VENV/bin/pip" install --quiet "ansible-core<2.14" "ansible-runner<2.4"
fi

pkill -f "box_agent_agent.py" 2>/dev/null || true
sleep 1
PYTHONPATH="" nohup "$VENV/bin/python" /root/box_agent_agent.py \
    --config /root/box_agent_config.json > /root/box_agent.log 2>&1 &
sleep 2
echo "box-agent started (pid $(pgrep -f 'box_agent_agent.py' | head -1 || echo '?'))"
