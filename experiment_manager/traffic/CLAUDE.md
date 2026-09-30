# Adding a traffic plugin

Traffic plugins generate benign background activity on the victim hosts, so the attacker's actions
aren't the only thing in the telemetry. The plugin type exists, and `plugins/caldera_human/` is a
working implementation. The full extension guide is pending while the interface settles.

Until then, follow the same pattern as the other systems. Create a Python file in `plugins/`, and
initialize a class subclassed under `TrafficPlugin` (`plugins/base.py`) with a `config_type`. Copy
`plugins/caldera_human/` as the reference. See the root `../CLAUDE.md` for the shared plugin model, and
`attacker/CLAUDE.md` for the closest fully-documented example.
