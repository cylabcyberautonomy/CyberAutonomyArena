"""MHBench environment-plugin package.

The whole MHBench implementation (deployer / capacity sizing / collect / rotate / teardown) lives
inside this package, so the environment package root stays backend-neutral — MHBench is just one
plugin, not the environment interface. Importing this package registers the plugin (config_type="mhbench").
"""
from .mhbench import MHBenchEnvironment  # noqa: F401 — registers config_type="mhbench"
