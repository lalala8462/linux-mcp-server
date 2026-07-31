"""Lifecycle CLI validation and keyless package tests."""

import argparse
import importlib.util
import json
import os
import tarfile

from datetime import datetime
from datetime import timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from linux_mcp_server import managed_hosts_cli as ENTRYPOINT
from linux_mcp_server.host_registry import MANAGED_TOOL_NAMES
from tests.test_host_registry import capability_matrix
from tests.test_host_registry import ED25519_PUBLIC_KEY
from tests.test_host_registry import RSA_PUBLIC_KEY


SCRIPT = Path(__file__).parents[1] / "scripts" / "manage_linux_hosts.py"
SPEC = importlib.util.spec_from_file_location("manage_linux_hosts", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load managed-host lifecycle script")
MANAGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANAGER)


def test_installed_entrypoint_loads_source_cli():
    assert ENTRYPOINT._load_cli_module().WRAPPER_VERSION == MANAGER.WRAPPER_VERSION


def test_installed_entrypoint_delegates_to_bundled_cli(mocker):
    implementation = SimpleNamespace(main=mocker.Mock(return_value=0))
    mocker.patch.object(ENTRYPOINT, "_load_cli_module", autospec=True, return_value=implementation)

    assert ENTRYPOINT.main() == 0
    implementation.main.assert_called_once_with()


def discovery(alias: str = "server-1", major: int = 7) -> dict:
    legacy_rsa = major == 6
    return {
        "schema_version": 1,
        "alias": alias,
        "allowed_root": "/data",
        "os": {
            "id": "centos",
            "version": "6.5" if legacy_rsa else ("Stream 9" if major == 9 else str(major)),
            "major": major,
            "release_source": "/etc/redhat-release" if legacy_rsa else "/etc/os-release",
            "kernel": "2.6.32" if legacy_rsa else "3.10.0",
            "architecture": "x86_64",
        },
        "ssh": {
            "server_version": "OpenSSH_5.3p1" if legacy_rsa else "OpenSSH_7.4p1",
            "host_keys": [
                {
                    "type": "ssh-rsa" if legacy_rsa else "ssh-ed25519",
                    "public_key": RSA_PUBLIC_KEY if legacy_rsa else ED25519_PUBLIC_KEY,
                }
            ],
        },
        "runtime": {
            "python_executable": "/usr/bin/python",
            "python_version": "2.6.6" if legacy_rsa else "3.11.0",
        },
        "capabilities": capability_matrix(major),
        "collected_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }


def test_discover_bundle_contains_no_key_material(tmp_path):
    args = argparse.Namespace(alias="server-1", allowed_root="/data", output_dir=tmp_path)

    MANAGER.command_discover(args)

    bundle = tmp_path / "server-1-discovery.tar.gz"
    with tarfile.open(bundle, "r:gz") as archive:
        names = archive.getnames()
        runner_file = archive.extractfile("server-1-discovery/run-discovery.sh")
        assert runner_file is not None
        runner = runner_file.read().decode("utf-8")
    assert set(names) == {
        "server-1-discovery",
        "server-1-discovery/collect-host-profile.py",
        "server-1-discovery/run-discovery.sh",
    }
    assert "PRIVATE KEY" not in runner
    assert "ssh-keygen" not in runner
    assert (tmp_path / "server-1-discovery.tar.gz.sha256").is_file()


def test_discovery_import_requires_exact_alias_and_nineteen_tools():
    normalized = MANAGER.validate_discovery(discovery(), "server-1", "/data")

    assert set(normalized["capabilities"]) == MANAGED_TOOL_NAMES

    invalid = discovery(alias="other")
    with pytest.raises(RuntimeError, match="alias"):
        MANAGER.validate_discovery(invalid, "server-1", "/data")

    legacy_without_runtime = discovery()
    del legacy_without_runtime["runtime"]
    normalized = MANAGER.validate_discovery(legacy_without_runtime, "server-1", "/data")
    assert "runtime" not in normalized


@pytest.mark.parametrize(
    ("major", "expected_source", "expected_ssh_type"),
    [
        (6, "/etc/redhat-release", "ssh-rsa"),
        (7, "/etc/os-release", "ssh-ed25519"),
        (8, "/etc/os-release", "ssh-ed25519"),
        (9, "/etc/os-release", "ssh-ed25519"),
    ],
)
def test_sanitized_centos_discovery_fixtures(major, expected_source, expected_ssh_type):
    normalized = MANAGER.validate_discovery(discovery(major=major), "server-1", "/data")

    assert normalized["os"]["major"] == major
    assert normalized["os"]["release_source"] == expected_source
    assert normalized["ssh"]["host_keys"][0]["type"] == expected_ssh_type
    assert set(normalized["capabilities"]) == MANAGED_TOOL_NAMES


def test_public_key_validation_rejects_dsa_and_control_characters():
    with pytest.raises(RuntimeError, match="Ed25519 and RSA"):
        MANAGER.normalize_public_key("ssh-dss QUFBQUFBQUFBQUFBQUFBQUFB")
    with pytest.raises(RuntimeError, match="Invalid SSH public key"):
        MANAGER.normalize_public_key("ssh-ed25519 QUFB\nQUFB")


def test_centos6_host_key_selection_requires_rsa():
    payload = discovery()
    payload["os"]["major"] = 6
    trusted = payload["ssh"]["host_keys"][0]["public_key"]

    with pytest.raises(RuntimeError, match="ssh-rsa"):
        MANAGER.select_host_key(payload, trusted, 6)


def test_verification_results_require_all_profile_outcomes(tmp_path):
    from tests.test_host_registry import make_profile

    profile = make_profile(tmp_path, major=7)
    results = {
        "schema_version": 1,
        "alias": profile.alias,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "tools": {name: {"outcome": "success", "reason": "matched profile"} for name in MANAGED_TOOL_NAMES},
    }

    MANAGER.accept_verification_results(profile, results)
    results["tools"]["read_file"]["outcome"] = "failed"
    results["tools"]["read_file"]["reason"] = "permission_denied"
    with pytest.raises(RuntimeError, match=r"read_file\(permission_denied\)"):
        MANAGER.accept_verification_results(profile, results)


@pytest.mark.parametrize(
    ("rendered", "is_error", "expected"),
    [
        ("Error running command: [Errno 13] Permission denied", True, "permission_denied"),
        ("tool call failed: Transport closed", True, "transport_closed"),
        ("timed out awaiting tools/call", True, "command_timeout"),
        ("Authentication failed for server-1", True, "authentication_failed"),
        ("", False, "empty_output"),
        ("Error calling tool", True, "tool_error"),
        ("unexpected text", False, "profile_mismatch"),
    ],
)
def test_classifies_verification_failures_without_retaining_payload(rendered, is_error, expected):
    assert MANAGER.classify_verification_failure(rendered, is_error=is_error) == expected


def test_prepare_package_contains_public_key_but_not_private_key(tmp_path, monkeypatch):
    registry = tmp_path / "registry"
    host_dir = registry / "server-1"
    registration = {
        "schema_version": 1,
        "alias": "server-1",
        "address": "192.0.2.10",
        "port": 22,
        "user": "codex-ro",
        "allowed_root": "/data",
        "discovery_bundle_sha256": "a" * 64,
        "discovery": discovery(),
    }
    MANAGER.atomic_json(host_dir / "discovery.json", registration)
    trusted_key = tmp_path / "host.pub"
    trusted_key.write_text(
        discovery()["ssh"]["host_keys"][0]["public_key"] + "\n",
        encoding="ascii",
    )

    def fake_generate_client_key(target_dir, major):
        assert major == 7
        private_key = target_dir / "id_ed25519"
        private_key.write_text("PRIVATE TEST FIXTURE\n", encoding="ascii")
        os.chmod(private_key, 0o600)
        Path(str(private_key) + ".pub").write_text(
            discovery()["ssh"]["host_keys"][0]["public_key"] + "\n",
            encoding="ascii",
        )
        return "ed25519", private_key

    monkeypatch.setattr(MANAGER, "generate_client_key", fake_generate_client_key)
    output_dir = tmp_path / "bundles"
    args = argparse.Namespace(
        registry=registry,
        alias="server-1",
        trusted_host_key_file=trusted_key,
        output_dir=output_dir,
        accept_incomplete=False,
        allow_rsa=False,
    )

    MANAGER.command_prepare(args)

    with tarfile.open(output_dir / "server-1-deployment.tar.gz", "r:gz") as archive:
        names = archive.getnames()
        files = [archive.extractfile(name) for name in names if archive.getmember(name).isfile()]
        manifest_file = archive.extractfile("server-1-deployment/MANIFEST.json")
        assert manifest_file is not None
        manifest = json.loads(manifest_file.read())
        assert all(file is not None for file in files)
        contents = b"".join(file.read() for file in files if file is not None)
    assert any(name.endswith("id_ed25519.pub") for name in names)
    assert manifest["wrapper_version"] == MANAGER.WRAPPER_VERSION
    assert "linux-mcp-readonly.py" in manifest["files"]
    assert not any(name.endswith("/id_ed25519") for name in names)
    assert b"PRIVATE TEST FIXTURE" not in contents

    rebuilt = output_dir / "server-1-deployment-v2.tar.gz"
    MANAGER.command_rebuild_deployment(
        argparse.Namespace(
            registry=registry,
            alias="server-1",
            output=rebuilt,
        )
    )

    assert rebuilt.is_file()
    with tarfile.open(rebuilt, "r:gz") as archive:
        rebuilt_names = archive.getnames()
        rebuilt_contents = b"".join(
            file.read()
            for name in rebuilt_names
            if archive.getmember(name).isfile()
            for file in [archive.extractfile(name)]
            if file is not None
        )
    assert not any(name.endswith("/id_ed25519") for name in rebuilt_names)
    assert b"PRIVATE TEST FIXTURE" not in rebuilt_contents
    with pytest.raises(RuntimeError, match="already exists"):
        MANAGER.command_rebuild_deployment(
            argparse.Namespace(
                registry=registry,
                alias="server-1",
                output=rebuilt,
            )
        )
