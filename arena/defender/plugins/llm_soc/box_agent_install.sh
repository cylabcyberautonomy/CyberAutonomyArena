#!/usr/bin/env bash
# Box-side bootstrap for the defender box agent (the defender's in-environment effector).
#
# The defender box is Ubuntu 20.04 / py3.8 with BROKEN apt (the cloud mirror has no Release file) and NO
# venv module — but WORKING pip + PyPI egress. So skip venv/apt entirely: pip-install ansible into the
# user site and run the agent with the system python3. The agent is SELF-CONTAINED (imports no Perry
# Python, only ansible_runner + the shipped ansible/ YAMLs), so py3.8 is fine with ansible-core<2.14
# (2.14+ needs a py3.9 control node). prepare_box_agent has placed /root/box_agent_agent.py, /root/ansible/,
# /root/scoped_key and /root/box_agent_config.json. Idempotent; always (re)starts the agent.
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

if ! python3 -c "import ansible_runner" >/dev/null 2>&1; then
    python3 -m pip install --user --quiet --upgrade pip 2>/dev/null || true
    python3 -m pip install --user --quiet "ansible-core<2.14" "ansible-runner<2.4"
fi

pkill -f "box_agent_agent.py" 2>/dev/null || true
sleep 1
# ansible_runner shells to the ansible-playbook binary via PATH (installed to ~/.local/bin by pip --user),
# so the agent process must carry that PATH. PYTHONPATH cleared so nothing shadows the stdlib/site imports.
PATH="$HOME/.local/bin:$PATH" PYTHONPATH="" nohup python3 /root/box_agent_agent.py \
    --config /root/box_agent_config.json > /root/box_agent.log 2>&1 &
sleep 2
echo "box-agent started (pid $(pgrep -f 'box_agent_agent.py' | head -1 || echo '?'))"
