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
COLLECTOR_SPEC = importlib.util.spec_from_file_location("collect_host_profile", MANAGER.COLLECTOR)
if COLLECTOR_SPEC is None or COLLECTOR_SPEC.loader is None:
    raise RuntimeError("unable to load host profile collector")
COLLECTOR = importlib.util.module_from_spec(COLLECTOR_SPEC)
COLLECTOR_SPEC.loader.exec_module(COLLECTOR)


def test_installed_entrypoint_loads_source_cli():
    assert ENTRYPOINT._load_cli_module().WRAPPER_VERSION == MANAGER.WRAPPER_VERSION


def test_installed_entrypoint_delegates_to_bundled_cli(mocker):
    implementation = SimpleNamespace(main=mocker.Mock(return_value=0))
    mocker.patch.object(ENTRYPOINT, "_load_cli_module", autospec=True, return_value=implementation)

    assert ENTRYPOINT.main() == 0
    implementation.main.assert_called_once_with()


def discovery(
    alias: str = "server-1",
    major: int = 7,
    *,
    roots: tuple[str, ...] = ("/data",),
    schema_version: int = 2,
) -> dict:
    legacy_rsa = major == 6
    payload = {
        "schema_version": schema_version,
        "alias": alias,
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
    if schema_version == 1:
        if len(roots) != 1:
            raise ValueError("schema version 1 supports one root")
        payload["allowed_root"] = roots[0]
    else:
        payload["allowed_roots"] = list(roots)
    return payload


def test_discover_bundle_contains_no_key_material(tmp_path):
    args = argparse.Namespace(alias="server-1", allowed_root=["/usr", "/data"], output_dir=tmp_path)

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
    assert "--allowed-root '/data' --allowed-root '/usr'" in runner
    assert (tmp_path / "server-1-discovery.tar.gz.sha256").is_file()


def test_collector_emits_schema_v2_and_validates_every_root(monkeypatch, capsys):
    checked_roots = []

    def fake_isdir(path):
        checked_roots.append(path)
        return path in {"/data", "/usr"}

    monkeypatch.setattr(COLLECTOR.os.path, "isdir", fake_isdir)
    monkeypatch.setattr(COLLECTOR, "detect_os", lambda: {"major": 7})
    monkeypatch.setattr(COLLECTOR, "detect_ssh", lambda: {"server_version": "test", "host_keys": []})
    monkeypatch.setattr(
        COLLECTOR,
        "detect_runtime",
        lambda: {"python_executable": "/usr/bin/python", "python_version": "3.11.0"},
    )

    def fake_capabilities(os_profile):
        return capability_matrix(os_profile["major"])

    monkeypatch.setattr(COLLECTOR, "detect_capabilities", fake_capabilities)
    monkeypatch.setattr(
        COLLECTOR.sys,
        "argv",
        ["collect-host-profile.py", "--alias", "server-1", "--allowed-root", "/usr", "--allowed-root", "/data"],
    )

    COLLECTOR.main()

    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 2
    assert payload["allowed_roots"] == ["/data", "/usr"]
    assert checked_roots == ["/usr", "/data"]


def test_storage_capability_checks_use_bounded_collector_directory(mocker):
    command_ok = mocker.patch.object(COLLECTOR, "command_ok", autospec=True, return_value=True)

    assert COLLECTOR.storage_capabilities_ok() == (True, True, True)
    assert command_ok.call_args_list == [
        mocker.call(
            ("find", COLLECTOR.CAPABILITY_PROBE_ROOT, "-mindepth", "1", "-maxdepth", "1"),
            require_output=False,
        ),
        mocker.call(("du", "-b", "--one-file-system", "--max-depth=0", COLLECTOR.CAPABILITY_PROBE_ROOT)),
        mocker.call(("stat", "--dereference", "--format", "%s", "--", COLLECTOR.CAPABILITY_PROBE_ROOT)),
    ]
    assert all("/usr" not in call.args[0] and "/data" not in call.args[0] for call in command_ok.call_args_list)


@pytest.mark.parametrize(
    ("failed_command", "expected"),
    [
        ("find", (False, True, True)),
        ("du", (True, False, True)),
        ("stat", (True, True, False)),
    ],
)
def test_storage_capability_checks_preserve_failures(mocker, failed_command, expected):
    command_ok = mocker.patch.object(
        COLLECTOR,
        "command_ok",
        autospec=True,
        side_effect=lambda args, require_output=True: args[0] != failed_command,
    )

    assert COLLECTOR.storage_capabilities_ok() == expected
    assert command_ok.call_count == 3


def test_discovery_import_requires_exact_alias_and_nineteen_tools():
    normalized = MANAGER.validate_discovery(discovery(), "server-1", ("/data",))

    assert set(normalized["capabilities"]) == MANAGED_TOOL_NAMES
    assert normalized["schema_version"] == 2
    assert normalized["allowed_roots"] == ["/data"]

    invalid = discovery(alias="other")
    with pytest.raises(RuntimeError, match="alias"):
        MANAGER.validate_discovery(invalid, "server-1", ("/data",))

    legacy_without_runtime = discovery(schema_version=1)
    del legacy_without_runtime["runtime"]
    normalized = MANAGER.validate_discovery(legacy_without_runtime, "server-1", ("/data",))
    assert "runtime" not in normalized

    with pytest.raises(RuntimeError, match="requested roots"):
        MANAGER.validate_discovery(discovery(roots=("/data", "/usr")), "server-1", ("/data",))


@pytest.mark.parametrize(
    "roots",
    (
        [],
        ["/"],
        ["/data", "/data"],
        ["/data", "/data/log"],
        [f"/root-{index}" for index in range(17)],
    ),
)
def test_allowed_roots_validation_rejects_unsafe_lists(roots):
    with pytest.raises(RuntimeError, match="allowed_roots"):
        MANAGER.validate_allowed_roots(roots)


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
    normalized = MANAGER.validate_discovery(discovery(major=major), "server-1", ("/data",))

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


def test_verification_paths_require_sample_coverage_for_every_root(tmp_path):
    from tests.test_host_registry import make_profile

    payload = make_profile(tmp_path).model_dump(mode="json")
    payload["allowed_roots"] = ["/data", "/usr"]
    profile = MANAGER.HostProfile.model_validate(payload)

    MANAGER.validate_verification_paths(
        profile,
        [Path("/data/sample.txt"), Path("/usr/share/sample.txt")],
        Path("/data/app.log"),
    )
    with pytest.raises(RuntimeError, match="Missing --sample-file coverage"):
        MANAGER.validate_verification_paths(
            profile,
            [Path("/data/sample.txt")],
            Path("/data/app.log"),
        )
    with pytest.raises(RuntimeError, match="outside managed allowed_roots"):
        MANAGER.validate_verification_paths(
            profile,
            [Path("/data/sample.txt"), Path("/usr/../etc/passwd")],
            Path("/data/app.log"),
        )


def test_prepare_package_contains_public_key_but_not_private_key(tmp_path, monkeypatch):
    registry = tmp_path / "registry"
    host_dir = registry / "server-1"
    registration = {
        "schema_version": 2,
        "alias": "server-1",
        "address": "192.0.2.10",
        "port": 22,
        "user": "codex-ro",
        "allowed_roots": ["/data", "/usr"],
        "discovery_bundle_sha256": "a" * 64,
        "discovery": discovery(roots=("/data", "/usr")),
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
        policy_file = archive.extractfile("server-1-deployment/policy.json")
        assert manifest_file is not None
        assert policy_file is not None
        manifest = json.loads(manifest_file.read())
        policy = json.loads(policy_file.read())
        assert all(file is not None for file in files)
        contents = b"".join(file.read() for file in files if file is not None)
    assert any(name.endswith("id_ed25519.pub") for name in names)
    assert manifest["wrapper_version"] == MANAGER.WRAPPER_VERSION
    assert "linux-mcp-readonly.py" in manifest["files"]
    assert policy == {"allowed_roots": ["/data", "/usr"], "read_mode": "user"}
    assert "linux-mcp-privileged-read" in manifest["files"]
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
    privileged_bundle = output_dir / "server-1-privileged.tar.gz"
    key_before = (host_dir / "id_ed25519").read_bytes()
    MANAGER.command_rebuild_deployment(
        argparse.Namespace(registry=registry, alias="server-1", output=privileged_bundle, read_mode="privileged")
    )
    assert (host_dir / "id_ed25519").read_bytes() == key_before
    profile = MANAGER.HostProfile.model_validate(MANAGER.read_json(host_dir / "profile.json"))
    assert profile.read_mode == "privileged"
    assert profile.allowed_roots == ("/data", "/usr")
    assert profile.verified_at is None
    with tarfile.open(privileged_bundle) as archive:
        policy_stream = archive.extractfile("server-1-deployment/policy.json")
        assert policy_stream is not None
        assert json.loads(policy_stream.read()) == {"allowed_roots": ["/data", "/usr"], "read_mode": "privileged"}
    with pytest.raises(RuntimeError, match="already exists"):
        MANAGER.command_rebuild_deployment(
            argparse.Namespace(
                registry=registry,
                alias="server-1",
                output=rebuilt,
            )
        )


def test_privileged_verification_requires_every_boundary_check(tmp_path):
    from tests.test_host_registry import make_profile

    payload = make_profile(tmp_path).model_dump(mode="json")
    payload["read_mode"] = "privileged"
    profile = MANAGER.HostProfile.model_validate(payload)
    results = {
        "schema_version": 1,
        "alias": profile.alias,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "tools": {name: {"outcome": "success", "reason": "matched profile"} for name in MANAGED_TOOL_NAMES},
        "read_checks": {name: "success" for name, _, _, _ in MANAGER.privileged_verification_cases(profile)},
    }
    MANAGER.accept_verification_results(profile, results)
    results["read_checks"]["root_1_root_file"] = "failed"
    with pytest.raises(RuntimeError, match="boundary checks"):
        MANAGER.accept_verification_results(profile, results)
    del results["read_checks"]
    with pytest.raises(RuntimeError, match="schema"):
        MANAGER.accept_verification_results(profile, results)


def test_privileged_verification_refuses_imported_success(tmp_path):
    from tests.test_host_registry import make_profile

    registry = tmp_path / "registry"
    directory = registry / "server-1"
    payload = make_profile(tmp_path).model_dump(mode="json")
    payload["read_mode"] = "privileged"
    MANAGER.atomic_json(directory / "profile.json", payload)
    with pytest.raises(RuntimeError, match="live MCP"):
        MANAGER.command_verify(
            argparse.Namespace(registry=registry, alias="server-1", results_json=tmp_path / "fake.json")
        )


async def test_verification_server_exposes_only_nineteen_readonly_tools(mcp_client):
    tools = await mcp_client.list_tools()
    assert {tool.name for tool in tools} == MANAGED_TOOL_NAMES
    assert all(tool.annotations is not None and tool.annotations.readOnlyHint is True for tool in tools)


def test_inventory_displays_target_and_read_mode(tmp_path, capsys):
    from tests.test_host_registry import make_profile

    registry = tmp_path / "registry"
    host = registry / "server-1"
    host.mkdir(parents=True)
    profile = make_profile(host).model_dump(mode="json")
    profile["read_mode"] = "privileged"
    MANAGER.atomic_json(host / "profile.json", profile)
    MANAGER.atomic_json(
        host / "discovery.json",
        {
            "alias": "server-1",
            "address": "192.0.2.10",
            "port": 2222,
            "discovery": discovery(),
        },
    )
    MANAGER.command_list(argparse.Namespace(registry=registry))
    output = capsys.readouterr().out
    assert all(value in output for value in ("server-1", "192.0.2.10", "2222", "codex-ro", "privileged"))
    assert "private test fixture" not in output
