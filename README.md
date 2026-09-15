# Experiment Harness

A dashboard and backend for running attacker/defender experiments across network environments.

## Architecture overview

```
dashboard.py          — browser UI (port 8080 by default)
experiment_manager/   — FastAPI backend (port 8000)
  main.py             — orchestrates experiment lifecycle
  config.py           — loads config.yaml
  attacker/plugins/   — attacker plugin implementations
  defender/plugins/   — defender plugin implementations
experiment_registry.yaml  — live state of all experiments
output/               — per-experiment logs and results
```

The dashboard is a thin proxy: it reads `experiment_registry.yaml` for the live view and forwards form submissions to the experiment manager's REST API.

---

## Quick start

**1. Install dependencies**

```bash
cd experiment_harness
uv sync
```

**2. Edit `config.yaml`** (see [Config reference](#config-reference) below)

**3. Start the experiment manager** (backend)

```bash
uv run uvicorn experiment_manager.main:app --port 8000
```

On startup the manager tears down any leftover OpenStack resources and clears the registry, so start it before submitting anything.

**4. Start the dashboard** (frontend)

```bash
uv run python dashboard.py --port 8080
```

Open `http://localhost:8080` in a browser.

---

## Config reference

`config.yaml` is loaded once at startup by the experiment manager. The dashboard also reads a subset of it to find environment specs.

**Repo paths** — point these at the relevant codebases on your machine:

| Key | What it points at |
|---|---|
| `incalmo_dir` | Incalmo repo (attacker framework) |
| `incalmo_python` | Python interpreter for Incalmo. Defaults to `<incalmo_dir>/.venv/bin/python` if omitted. |
| `mhbench_dir` | MHBench repo. Environment specs are resolved as `<mhbench_dir>/environments/<spec>.json`. |
| `deception_dir` | Deception/defender repo |
| `deception_python` | Python interpreter for the defender. Defaults to `<deception_dir>/.venv/bin/python` if omitted. |
| `host_ip` | The host machine's IP address, passed to defender plugins as `management_ip`. |

**Tunable parameters** — adjust these to control how the harness runs experiments:

| Key | Default | Effect |
|---|---|---|
| `max_concurrent_experiments` | `1` | How many experiments may deploy or run at the same time. Teardowns are always prioritized over new deployments when the limit is reached. |
| `max_retries` | `3` | How many times a failed experiment is automatically retried. Set to `0` to disable retries. |

---

## Using the dashboard

### Experiments tab

The left tab shows all experiments in the registry. It auto-refreshes every 5 seconds. Each row shows:

- **Name** — auto-generated from your choices, or prefixed with the name you set
- **Status** — Queued / Deploying / Running / Finished / Error
- **Environment** — the spec path used for this run
- **Attacker** — strategy or model name
- **Created / Updated** — timestamps in EST

### Submit tab

Use this to queue new experiments. The form has four sections:

#### 1. Environments

Pick one or more network environments from the left panel. Environments are discovered from `<mhbench_dir>/environments/` — JSON files in subdirectories are grouped by subdirectory name.

- Use the **group dropdown** to switch between environment groups (e.g. `generated`, `hand_crafted`).
- **Select all** / **Clear** operate on the current group only.
- Selected environments appear as chips on the right; click ✕ to remove one.

#### 2. Attackers

Choose a plugin type from the **Type** dropdown, fill in its fields, then click **+ Add attacker**. The added configuration appears as a chip on the right.

You can add multiple attacker configs — each one will be crossed with every defender and every environment.

#### 3. Defenders

Same workflow as attackers. Click **+ No defender** to run an attacker without any defender in the loop.

You can mix "real" defenders and "no defender" in the same batch.

#### 4. Run options

| Field | Effect |
|---|---|
| **Repeats** | Run the full attacker × defender × environment matrix this many times |
| **Name prefix** | Prepended to every generated experiment name. Leave blank for no prefix. |

The total number of experiments submitted is shown before the submit button fires:
`attackers × defenders × environments × repeats`

#### Submitting

Click **Submit experiments**. A log box below the button shows each experiment's submission result (OK or error) in real time. The Experiments tab updates automatically once they are queued.

---

## Adding plugins

Plugins are discovered automatically — any Python package placed inside `attacker/plugins/` or `defender/plugins/` is imported at startup. You do not need to edit any registry file.

Each plugin must implement `ui_schema()`, which declares what configuration options the plugin needs to deploy an attacker or defender. The dashboard reads these schemas at startup to build the Submit form — the type dropdown and all its fields come directly from the registered plugins. A plugin without a valid `ui_schema()` will not appear in the dashboard.

### Attacker plugin

Create a new package under `experiment_manager/attacker/plugins/<your_plugin>/`:

```
experiment_manager/attacker/plugins/
  my_attacker/
    __init__.py      ← leave empty or re-export the class
    my_attacker.py   ← plugin implementation
```

`my_attacker.py`:

```python
import asyncio
from pathlib import Path
from typing import Literal, Optional

from ..base import AttackerPlugin
from ....config import ExperimentManagerConfig
from ....environment import DeployedEnvironment
from ....ui_schema import PluginUISchema


class MyAttacker(AttackerPlugin, config_type="my_attacker"):
    type: Literal["my_attacker"]
    some_option: str

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "my_attacker",
            "label": "My Attacker",
            "cartesian_product": False,
            "fields": [
                {
                    "field_type": "flat_checkboxes",
                    "label": "Some option",
                    "key": "some_option",
                    "options": ["fast", "slow"],
                },
            ],
        }

    def build_config(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
        c2c_url: str,
    ) -> dict:
        return {
            "name": experiment_name,
            "option": self.some_option,
            "environment": environment.spec if environment else "none",
        }

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
        c2c_url: str,
    ) -> asyncio.subprocess.Process:
        log_path = cfg.output_dir / experiment_name / "attacker" / "attacker.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        return await asyncio.create_subprocess_exec(
            "my-attacker-binary", str(config_path),
            stdout=open(log_path, "a"),
            stderr=asyncio.subprocess.STDOUT,
        )
```

Key points:

- `config_type="my_attacker"` in the class declaration registers it. The same string must appear as `type` in `ui_schema()` and as the `type` literal.
- If your attacker needs a C2 server, override `launch_c2c`, `wait_c2c_ready`, `wait_c2c_agent`, and `stop_c2c`. See the existing `_IncalmoAttacker` base class for a reference implementation.
- `run()` must return an `asyncio.subprocess.Process`. The manager waits for it to exit; exit code 0 → Finished, anything else → Error.

### Defender plugin

Create a new package under `experiment_manager/defender/plugins/<your_plugin>/`:

```
experiment_manager/defender/plugins/
  my_defender/
    __init__.py
    my_defender.py
```

`my_defender.py`:

```python
import asyncio
from pathlib import Path
from typing import Literal, Optional

from ..base import DefenderPlugin
from ....config import ExperimentManagerConfig
from ....environment import DeployedEnvironment
from ....ui_schema import PluginUISchema


class MyDefender(DefenderPlugin, config_type="my_defender"):
    type: Literal["my_defender"]
    strategy: str

    @classmethod
    def ui_schema(cls) -> PluginUISchema:
        return {
            "config_type": "my_defender",
            "label": "My Defender",
            "cartesian_product": False,
            "fields": [
                {
                    "field_type": "flat_checkboxes",
                    "label": "Strategy",
                    "key": "strategy",
                    "options": ["passive", "active"],
                },
            ],
        }

    def build_config(
        self,
        experiment_name: str,
        environment: Optional[DeployedEnvironment],
    ) -> dict:
        return {
            "experiment_name": experiment_name,
            "strategy": self.strategy,
            "topology_spec": environment.topology_spec if environment else None,
        }

    async def run(
        self,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
    ) -> asyncio.subprocess.Process:
        log_path = cfg.output_dir / experiment_name / "defender" / "defender.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        return await asyncio.create_subprocess_exec(
            "my-defender-binary", str(config_path),
            stdout=open(log_path, "a"),
            stderr=asyncio.subprocess.STDOUT,
        )
```

The manager automatically injects `deception_dir`, `management_ip`, and `log_dir` into the config dict before writing it to disk (via `run_defender` in `defender/defender.py`), so you don't need to include those in `build_config`.

### UI schema field types

| `field_type` | Renders as | Value in config |
|---|---|---|
| `flat_checkboxes` | Checkbox list | Single string (one checked item) or list (multiple) |
| `grouped_checkboxes` | Grouped checkbox list with per-group select-all | Same as above |
| `text_with_suggestions` | Text input with datalist | String |
| `key_value_pairs` | Repeating key/value rows | `dict[str, int]` |
| `json` | Free-text input, parsed as JSON | Any JSON value |

Setting `cartesian_product: True` in the schema causes the dashboard to generate one config per combination of all selected checkbox values across all checkbox fields. Useful for sweeping attacker LLM × abstraction level combinations.

---

## Output structure

Each experiment writes to `output/<experiment_name>/`:

```
output/<experiment_name>/
  experiment/
    experiment_config.json   ← full Pydantic dump of the Experiment model
    result.json              ← {"status": "Finished"} or {"status": "Error"}
  attacker/
    attacker_config.json     ← config dict from build_config()
    attacker.log             ← stdout+stderr of the attacker process
    c2c_server.log           ← C2 container logs (if applicable)
  defender/
    defender_config.json     ← config dict from build_config()
    defender.log             ← stdout+stderr of the defender process
```

Every failed experiment's output folder is moved to `output/failed/<experiment_name>/`. If the retry budget is not exhausted, the next attempt then runs fresh under `output/`.

After collection, the harness also fetches each host's ground-truth logs into
`output/<experiment_name>/environment/<host>/` (auth.log, syslog, `audit.log`, cmdlog,
`/etc/passwd`+`/etc/group` id maps, and the `auditctl-rules.txt` / `auditctl-status.txt`
sensor-state dumps).

---

## Detections

The collected auditd logs can be scored against the Sigma Linux ruleset to produce MITRE
ATT&CK-mapped detections, via [Zircolite](https://github.com/wagga40/Zircolite) (which runs
Sigma directly over raw auditd `.log` files — no SIEM required).

**One-time setup** (the tool prints these exact commands if Zircolite is missing):

```bash
git clone --depth 1 https://github.com/wagga40/Zircolite.git ~/Zircolite
cd ~/Zircolite && uv venv .venv && uv pip install -p .venv/bin/python -r requirements.txt
```

Point `zircolite_dir` in `config.yaml` at the checkout (defaults to `~/Zircolite`).

**Run:**

```bash
uv run python detect.py <experiment_name>   # one experiment
uv run python detect.py --all               # every experiment with collected logs
```

Output lands under `output/<experiment_name>/detections/`:

```
detections/
  <host>.json            ← raw Zircolite detections for that host
  <host>.zircolite.log   ← Zircolite run log
  summary.json           ← per-host + per-rule + ATT&CK rollup (machine-readable)
  summary.md             ← the same, human-readable
```

`summary.md` gives a per-host hit table, every Sigma rule that fired (with level and which hosts),
and a MITRE ATT&CK technique tally ranked by matched events.

**Rulesets.** Two are applied together: the stock SigmaHQ Linux ruleset (`rules_linux.json`,
process-execution/discovery heavy) and a set of **custom Sigma rules** in
`experiment_manager/detection/sigma_rules/` that cover MHBench's high-value auditd keys the stock
ruleset misses — credential access (`/etc/shadow`, root SSH key), fileless execution
(`memfd_create`), timestomping, failed-connect lateral-movement probes, eBPF/kernel-module loads,
and failed privilege changes. These are portable Sigma (convertible to Splunk/Elastic/Sentinel),
not Zircolite-specific. Each rule excludes the known-good system daemons (systemd, sshd,
unix_chkpwd, splunkd, snapd…) so it fires on genuine misuse rather than benign telemetry — a raw
auditd key alone is telemetry, not a detection.

**Attack-window scoping.** Provisioning and teardown run the same benign commands (`uname`,
key installs, service starts) on *every* host, which low-fidelity Sigma discovery rules flag as
false positives. To avoid this, each host's auditd log is filtered to the attacker's run window
(`attacker.started_at`…`finished_at` from `experiment/experiment_result.json`) before scoring, so
only activity during the actual attack is counted. `summary.md` states which mode was used and,
per host, how many audit lines fell inside the window. If the attacker timestamps are missing the
runner falls back to scoring the full log (and says so) rather than dropping data silently.

**Interpreting a non-hit:** a rule not firing has three possible causes — the attacker didn't do
it, the audit rule never loaded, or the event was dropped. Cross-check the host's
`environment/<host>/auditctl-rules.txt` (was the relevant rule loaded?) and `auditctl-status.txt`
(was the `lost` count non-zero?) before treating a non-hit as a true negative.
