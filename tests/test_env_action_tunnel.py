"""The harness-initiated ssh -R reverse tunnel exposing the env-action TCP server to a box-resident defender."""
from arena.defender.env_spec import DefenderSetupAccess
from arena.env_action_server import build_reverse_tunnel_cmd, pick_free_tcp_port


def _box_access():
    return DefenderSetupAccess(
        name="defender_box", host="10.0.0.9", user="root", ssh_key="/k",
        ssh_common_args='-o ProxyCommand="ssh -W %h:%p -i /k root@bastion"')


def test_reverse_tunnel_cmd_is_loopback_bound_single_forward_fail_loud():
    cmd = build_reverse_tunnel_cmd(_box_access(), box_port=5001, tcp_port=5002)
    assert cmd[0] == "ssh"
    # explicit 127.0.0.1 bind on the box side of -R, forwarding to the harness loopback
    assert "-R" in cmd and "127.0.0.1:5001:127.0.0.1:5002" in cmd
    # single forward only — no -D/-L
    assert "-D" not in cmd and "-L" not in cmd
    assert sum(1 for c in cmd if c == "-R") == 1
    # fail loud if the forward can't bind
    assert "ExitOnForwardFailure=yes" in cmd
    # keepalive + no remote shell
    assert any("ServerAliveInterval" in c for c in cmd) and any("ServerAliveCountMax" in c for c in cmd)
    assert "-N" in cmd
    assert "/k" in cmd and "root@10.0.0.9" in cmd


def test_pick_free_tcp_port_is_an_ephemeral_port():
    p = pick_free_tcp_port()
    assert isinstance(p, int) and 1024 <= p <= 65535
    assert isinstance(pick_free_tcp_port(), int)
