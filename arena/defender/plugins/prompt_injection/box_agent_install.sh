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

# ansible-core bundles only ansible.builtin; the honey-cred ssh-key playbook (setup_ssh_keys.yml) uses the
# authorized_key module from the ansible.posix collection, so install it (to ~/.ansible/collections, which
# is on ansible's default collection path). Without it AddHoneyCredentials fails with "couldn't resolve
# module/action 'authorized_key'". Pinned <1.6.0: ansible.posix 1.6.0 raised requires_ansible to >=2.15,
# which the box's ansible-core 2.13.13 doesn't meet (installs but warns "does not support 2.13.13"); every
# version <1.6.0 requires >=2.9, so this resolves to 1.5.4 and supports the box cleanly. Idempotent.
#
# GATE: this install MUST succeed before the agent starts. A silently-skipped install (galaxy flakiness)
# used to leave the agent serving AddHoneyCredentials that fail rc=4 mid-run. Retry the fetch for transient
# galaxy errors, then HARD-VERIFY the collection is present and exit non-zero if not — the box bootstrap
# then fails loudly (prepare_box_agent raises), so the defender fails to arm instead of arming half-broken.
if ! ansible-galaxy collection list 2>/dev/null | grep -q "ansible.posix"; then
    attempt=0
    while [ "$attempt" -lt 3 ]; do
        attempt=$((attempt + 1))
        if ansible-galaxy collection install "ansible.posix:>=1.4.0,<1.6.0" >/dev/null 2>&1 \
           || ansible-galaxy collection install ansible.posix >/dev/null 2>&1; then
            break
        fi
        echo "ansible.posix install attempt $attempt failed; retrying" >&2
        sleep 5
    done
fi
if ! ansible-galaxy collection list 2>/dev/null | grep -q "ansible.posix"; then
    echo "FATAL: ansible.posix collection not installed after retries; refusing to start the box agent" >&2
    echo "       (AddHoneyCredentials would fail rc=4). Check the box's egress to Ansible Galaxy." >&2
    exit 1
fi

pkill -f "box_agent_agent.py" 2>/dev/null || true
sleep 1
# ansible_runner shells to the ansible-playbook binary via PATH (installed to ~/.local/bin by pip --user),
# so the agent process must carry that PATH. PYTHONPATH cleared so nothing shadows the stdlib/site imports.
PATH="$HOME/.local/bin:$PATH" PYTHONPATH="" nohup python3 /root/box_agent_agent.py \
    --config /root/box_agent_config.json > /root/box_agent.log 2>&1 &
sleep 2
echo "box-agent started (pid $(pgrep -f 'box_agent_agent.py' | head -1 || echo '?'))"
