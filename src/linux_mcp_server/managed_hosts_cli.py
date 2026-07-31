"""Installed entry point for the bundled managed-host lifecycle CLI."""

from __future__ import annotations

import importlib.util

from pathlib import Path
from types import ModuleType
from typing import Callable


def _load_cli_module() -> ModuleType:
    module_path = Path(__file__).resolve().parent / "managed_assets" / "manage_linux_hosts.py"
    if not module_path.is_file():
        module_path = Path(__file__).resolve().parents[2] / "scripts" / "manage_linux_hosts.py"
    spec = importlib.util.spec_from_file_location("linux_mcp_server._managed_hosts_impl", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load managed-host lifecycle CLI: {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    implementation = _load_cli_module()
    cli_main: Callable[[], int] = implementation.main
    return cli_main()
