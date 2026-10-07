"""Regression guard: no plugin may read the management ("god") key off disk."""
from __future__ import annotations

import re
from pathlib import Path

_PLUGIN_ROOTS = ["attacker/plugins", "defender/plugins"]

# God-key read signatures (deliberately NOT matching the intended access["ssh_key"] pattern).
_PATTERNS = [
    re.compile(r"openstack_config\.ssh_key_path"),
    re.compile(r"gcp_config\.ssh_key_path"),
    re.compile(r"""\[['"]openstack['"]\]\[['"]ssh_key_path['"]\]"""),
    re.compile(r"""\[['"]gcp['"]\]\[['"]ssh_key_path['"]\]"""),
    re.compile(r"_mhbench_ssh_key|_mhb_ssh_key"),
    re.compile(r"id_ed25519"),
]

# Baseline of currently-known reads, keyed by plugin-relative path. Shrink it as fixes merge.
_BASELINE = {
}


def _plugins_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "arena"


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
    """Fail if a baselined file no longer reads the god key, so the guard tightens as fixes merge."""
    offenders = _offending_files()
    stale = [f for f in _BASELINE if f not in offenders]
    assert not stale, (
        "These baseline entries are no longer reading the god key (fix merged) — remove them from "
        "_BASELINE so the guard stays strict:\n" + "\n".join(f"  {f}" for f in stale)
    )
