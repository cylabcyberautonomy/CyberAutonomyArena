# CyberAutonomy Arena

A dashboard and backend for running attacker/defender experiments across network environments.

## Architecture overview

```
dashboard/server.py   — browser UI (port 8080 by default)
arena/   — FastAPI backend (port 8000)
  main.py             — orchestrates experiment lifecycle
  config.py           — loads config/config.yaml
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
cd cyberautonomy-arena
uv sync
```

**2. Create `config/config.yaml`** from the template, then edit the paths and `arena_host_ip`:

```bash
cp config/example_config.yaml config/config.yaml
```

[`config/example_config.yaml`](config/example_config.yaml) documents every field with its default; the [Config reference](#config-reference) below summarizes the common ones.

**3. Start the experiment manager** (backend)

```bash
uv run uvicorn arena.main:app --port 8000
```

On startup the manager clears the registry and, on OpenStack, deletes servers across all projects visible to its credentials along with internal networking resources. Use a dedicated cloud and confirm no other task owns resources before starting or restarting it. Restart the manager after plugin source changes to reload them.

**4. Start the dashboard** (frontend)

```bash
uv run python dashboard/server.py --port 8080 --url http://localhost:8000
```

Open `http://localhost:8080` in a browser.

---

## Submitting an experiment (API)

An experiment is submitted as a JSON body `POST`ed to the manager's `/experiments` endpoint (this is what
the dashboard's Submit tab builds for you). [`example_experiment.json`](example_experiment.json) is a
ready-to-edit template:

```bash
curl -X POST http://localhost:8000/experiments \
     -H 'Content-Type: application/json' \
     --data @example_experiment.json
```

The body pairs the four pluggable systems (see [`CLAUDE.md`](CLAUDE.md) for the plugin model):

| Field | Required | What it is |
|-------|----------|------------|
| `experiment_name` | yes | Unique name; also the output-dir name. Re-submitting an existing name needs `overwrite: true`. |
| `environment` | yes | `{environment_plugin, environment_spec}` — `environment_plugin` names a registered env plugin (`mhbench`); `environment_spec` is a topology path **relative to `mhbench_dir`** (e.g. `environments/instrumented/equifax_small_instrumented.json`). |
| `attacker_plugin` + `attacker_spec` | yes | The attacker as a `(plugin, spec)` pair. `attacker_spec` is that plugin's fields — an inline object (as here) **or** a path to a JSON/YAML file. |
| `defender` | no | Embedded `{type, ...}`; `type` names a registered defender (`llm_soc`, `deception`, `prompt_injection`, `velociraptor`, `canary`) and the rest are its fields. Omit for an undefended run. A defender needs an `*_instrumented` topology (it requires a defender box). |
| `traffic` | no | Embedded `{type, ...}` benign background traffic (`caldera_human`). Omit for none. |
| `trial`, `priority`, `teardown`, `overwrite`, `output_dir` | no | Scheduling / run options (`priority` higher = admitted sooner; `teardown: false` leaves the env standing; `overwrite: true` cancels+replaces a same-named run). |

Each selected plugin must have its code path set in `config.yaml` (see the Config reference below) — e.g.
the example above needs `incalmo_strategy_dir` (attacker) and `llm_soc_dir` (defender).

---

## Config reference

`config/config.yaml` is loaded once at startup by the arena. The dashboard also reads a subset of it to find environment specs. Copy [`config/example_config.yaml`](config/example_config.yaml) to `config/config.yaml` to start — it lists every field with its default. Only `mhbench_dir` and `arena_host_ip` are required; the per-plugin code paths are optional (set the ones for the plugins you run).

**Per-plugin code paths** — most plugins shell out to an external codebase (its own checkout + venv) that
the arena does not vendor, so you point the arena at it here. There is **one `*_dir` per plugin** (plus an
optional `*_python` override, defaulting to `<its_dir>/.venv/bin/python`). **Set only the paths for the
plugins you plan to use.** Redundancy is intentional: plugins that share a repo each name it, so no single
field silently backs several.

| Key | Needed by | What it points at |
|---|---|---|
| `mhbench_dir` | **always** (the environment backend) | MHBench repo. Topology paths are absolute or relative to this directory; also holds the scoped keys. A **defender** run needs a topology with a `defender_subnet` box and an MHBench revision supporting `request-ingress`. |
| `env_backend.mhbench_config` | Non-default MHBench configuration | MHBench `--config` (relative to `mhbench_dir`), e.g. `config/config.gcp.yaml`. Unset = MHBench's OpenStack default. |
| `incalmo_strategy_dir` (+`_python`) | `incalmo_strategy` attacker | Incalmo repo. |
| `incalmo_llm_dir` (+`_python`) | `incalmo_llm` attacker | Incalmo repo (same checkout as above; named per plugin). |
| `sliver_llm_dir` (+`_python`) | `sliver_llm` attacker | Sliver venv/checkout. Defaults to `<output_dir>/.sliver`. |
| `llm_soc_dir` (+`_python`) | `llm_soc` defender | Defense/Perry repo. |
| `deception_dir` (+`_python`) | `deception` defender | Defense/Perry repo (same checkout). |
| `prompt_injection_dir` (+`_python`) | `prompt_injection` defender | Defense/Perry repo (same checkout). |
| `velociraptor_dir` | `velociraptor` defender | Velociraptor repo (holds `bin/velociraptor`; a Go binary, no venv). |
| `arena_host_ip` | defenders | The arena/manager host's own IP (as seen from the deployed VMs), passed to defenders as `management_ip` for self-protection. **Not** the per-experiment bastion. |

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

Create a new package under `arena/attacker/plugins/<your_plugin>/`:

```
arena/attacker/plugins/
  my_attacker/
    __init__.py      ← leave empty or re-export the class
    my_attacker.py   ← plugin implementation
```

`my_attacker.py`:

```python
import asyncio
from pathlib import Path
from typing import Literal

from ..base import AttackerPlugin, PreparedAttacker
from ....config import ExperimentManagerConfig
from ...env_spec import AttackerEnvSpec
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
        env_spec: AttackerEnvSpec,
        prepared: PreparedAttacker,
    ) -> dict:
        return {
            "name": experiment_name,
            "option": self.some_option,
            "environment": env_spec.objective or "none",
        }

    async def run(
        self,
        prepared: PreparedAttacker,
        config_path: Path,
        experiment_name: str,
        cfg: ExperimentManagerConfig,
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

- `config_type="my_attacker"` in the class declaration registers it. The same string must appear as `config_type` in `ui_schema()` and as the `type` literal.
- If your attacker needs a C2 server, bring it up in `setup()` and wait for readiness before returning. Release its resources in `stop()` / `teardown()` and implement `sweep_stale_state()` for crash recovery. See `arena/attacker/plugins/incalmo_strategy/` for an example.
- `run()` must return an `asyncio.subprocess.Process`. The manager waits for it to exit; exit code 0 → Finished, anything else → Error.

### Defender plugin

Create a new package under `arena/defender/plugins/<your_plugin>/`:

```
arena/defender/plugins/
  my_defender/
    __init__.py
    my_defender.py
```

`my_defender.py`:

```python
import asyncio
from pathlib import Path
from typing import Literal

from ..base import DefenderPlugin, PreparedDefender
from ....config import ExperimentManagerConfig
from ...env_spec import DefenderEnvSpec
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
        env_spec: DefenderEnvSpec,
        prepared: PreparedDefender,
    ) -> dict:
        return {
            "experiment_name": experiment_name,
            "strategy": self.strategy,
            "objective": env_spec.objective,
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

The base class adds `defender_env_spec`, `defender_setup_access`, `management_ip`, `bastion_ip`, and `log_dir` in `run_setup()` before writing the runner config. Keep credential-bearing setup access out of `build_config()`.

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

