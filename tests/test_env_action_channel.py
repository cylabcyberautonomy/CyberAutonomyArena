"""The token'd TCP control-plane channel (env_action_server): token gate on TCP, token-free on UDS."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

from arena.env_action_server import handle_env_action, new_env_action_token


class _Reg:
    """Minimal registry: .get(name) returns the one live experiment or raises KeyError."""
    def __init__(self, exp):
        self._exp = exp

    def get(self, name):
        if name != self._exp.experiment_name:
            raise KeyError(name)
        return self._exp


def _exp(token="secret", serving=False):
    # serving=False so a token that PASSES stops at the serving-window (409), before action validation.
    return SimpleNamespace(experiment_name="e", _env_serving=serving, _env_action_token=token)


def _call(exp, **kw):
    payload = {"experiment_name": "e", "action": {}}
    return asyncio.run(handle_env_action(payload, registry=_Reg(exp), cfg=None, **kw))


# --------------------------------------------------------------------------- TCP path (token required)

def test_tcp_wrong_token_forbidden():
    res = _call(_exp(), token="nope", trusted_transport=False)
    assert res["status"] == 403 and res["ok"] is False


def test_tcp_missing_token_forbidden():
    res = _call(_exp(), token=None, trusted_transport=False)
    assert res["status"] == 403


def test_tcp_correct_token_passes_gate():
    # Correct token -> past the gate. Window closed -> 409 (proves the handler accepted the token).
    res = _call(_exp(token="secret"), token="secret", trusted_transport=False)
    assert res["status"] == 409


def test_tcp_rejected_when_experiment_has_no_token():
    # No token armed on the experiment: a TCP caller can never be let in, whatever it sends.
    res = _call(_exp(token=None), token="anything", trusted_transport=False)
    assert res["status"] == 403


# --------------------------------------------------------------------------- UDS path (token-free, unchanged)

def test_uds_needs_no_token():
    # trusted_transport=True (the UDS default): no token required. Window closed -> 409, not 403.
    res = _call(_exp(token=None), trusted_transport=True)
    assert res["status"] == 409


def test_uds_ignores_token_mismatch():
    # Even a mismatching token is irrelevant on the trusted UDS path.
    res = _call(_exp(token="secret"), token="nope", trusted_transport=True)
    assert res["status"] == 409


# --------------------------------------------------------------------------- token generation

def test_new_env_action_token_is_distinct_and_nonempty():
    a, b = new_env_action_token(), new_env_action_token()
    assert a and b and a != b and len(a) >= 20
