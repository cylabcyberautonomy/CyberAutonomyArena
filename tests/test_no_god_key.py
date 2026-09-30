"""Regression guard: no plugin may read the management ("god") key off disk.

The security model is per-system SCOPED keys: the environment issues each system a key that reaches
only its own hosts (attacker->foothold, defender->box+victims), and hands it to the plugin via the
injected SetupAccess. A plugin that instead reads the broad MHBench management key straight off disk
(openstack/gcp ssh_key_path, ~/.ssh/id_ed25519, or a _mhbench_ssh_key helper) bypasses all of that and
re-arms the god key — which, since a plugin may forward what it holds to its agent, hands the agent a
key to the whole environment.

This test does NOT stop a read at runtime; it's a tripwire so the fix can't silently rot back in: it
fails if any plugin file contains a god-key read that isn't in the documented baseline below.

BASELINE: the reads that exist RIGHT NOW on this branch, each pending an owner's fix on another branch
(or explicitly deferred). This branch (arena-refactor-env) predates the attacker/defender god-key
fixes, so those files still read the key here; the entries drop out as each fix merges in. When the
baseline is empty the guard is fully strict. To add a plugin: consume SetupAccess (access["ssh_key"]),
do NOT read a key path, and you never touch this file.
"""
from __future__ import annotations

import re
from pathlib import Path

_PLUGIN_ROOTS = ["attacker/plugins", "defender/plugins", "traffic/plugins"]

# God-key read signatures. Deliberately does NOT match the CORRECT pattern (access["ssh_key"] /
# access.get("ssh_key")) — consuming the injected scoped key is exactly what we want.
_PATTERNS = [
    re.compile(r"openstack_config\.ssh_key_path"),
    re.compile(r"gcp_config\.ssh_key_path"),
    re.compile(r"""\[['"]openstack['"]\]\[['"]ssh_key_path['"]\]"""),
    re.compile(r"""\[['"]gcp['"]\]\[['"]ssh_key_path['"]\]"""),
    re.compile(r"_mhbench_ssh_key|_mhb_ssh_key"),   # the read-the-mgmt-key-from-config helper (def or call)
    re.compile(r"id_ed25519"),                       # the default god-key path
]

# Baseline of currently-known reads, keyed by plugin-relative path. Shrink as fixes merge.
# Value = one-line reason so a reviewer knows why it's still here and when it goes away.
_BASELINE = {
    # Attacker plugins (cai, kali_c2) and defender runners (canary/deception/llm_soc/prompt_injection)
    # were fixed on arena-refactor / arena-refactor-defender and their fixes are now MERGED here — they
    # consume the injected scoped SetupAccess and no longer read the god key, so they are OUT of the
    # baseline (the guard is strict for them now).
    # Velociraptor — DEFERRED: its server runs on the bastion (can't be reached by a scoped key); the
    # fix is moving the server onto the defender box, then it consumes SetupAccess. Remove after that.
    "defender/plugins/velociraptor/velociraptor.py": "deferred: server-on-bastion, pending bastion->box migration",
    # Traffic — TABLED: needs its own victims-only scoped key (no adversary/agent, lower risk). Remove
    # when the traffic scoped key lands.
    "traffic/plugins/caldera_human/caldera_human.py": "tabled: needs a victims-only traffic scoped key",
}


def _plugins_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "experiment_manager"


def _offending_files() -> dict[str, list[str]]:
    """Return {plugin-relative path: [offending lines]} for every plugin .py with a god-key read."""
    base = _plugins_dir()
    offenders: dict[str, list[str]] = {}
    for root in _PLUGIN_ROOTS:
        for py in (base / root).rglob("*.py"):
            rel = str(py.relative_to(base))
            hits = [ln.strip() for ln in py.read_text().splitlines()
                    if any(p.search(ln) for p in _PATTERNS)]
            if hits:
                offenders[rel] = hits
    return offenders


def test_no_new_god_key_reads():
    """Fail if any plugin reads the management key off disk that isn't a documented baseline exception."""
    offenders = _offending_files()
    new = {f: lines for f, lines in offenders.items() if f not in _BASELINE}
    assert not new, (
        "New management-key ('god key') read in a plugin — plugins must consume the injected scoped "
        "key via SetupAccess (access['ssh_key']), never read a key path off disk:\n"
        + "\n".join(f"  {f}:\n    " + "\n    ".join(lines) for f, lines in new.items())
    )


def test_baseline_has_no_stale_entries():
    """Keep the baseline honest: if a listed file no longer reads the god key (its fix merged in),
    remove it from _BASELINE so the guard tightens. This fails when an entry is stale."""
    offenders = _offending_files()
    stale = [f for f in _BASELINE if f not in offenders]
    assert not stale, (
        "These baseline entries are no longer reading the god key (fix merged) — remove them from "
        "_BASELINE so the guard stays strict:\n" + "\n".join(f"  {f}" for f in stale)
    )
