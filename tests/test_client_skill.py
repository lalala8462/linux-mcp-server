"""公开 client Skill 的配置保留、可移植安装与卸载包隐私边界。"""

import hashlib
import importlib.util
import os
import runpy
import subprocess
import tarfile

from pathlib import Path
from types import ModuleType

import pytest


SCRIPTS = Path(__file__).parents[1] / "skills" / "linux-mcp-server-client" / "scripts"
TEMPLATE = Path(__file__).parents[1] / "config" / "codex-mcp-snippet.toml"


def load_script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"无法加载测试脚本：{name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BOOTSTRAP = load_script("bootstrap_wsl_mcp")
UNINSTALL = load_script("prepare_uninstall")


@pytest.fixture
def source_repository(tmp_path):
    repository = tmp_path / "source"
    (repository / "config").mkdir(parents=True)
    (repository / "config" / TEMPLATE.name).write_text(TEMPLATE.read_text(encoding="utf-8"), encoding="utf-8")
    (repository / "mcp-app" / "dist").mkdir(parents=True)
    (repository / "mcp-app" / "dist" / "run-script-app.html").write_text("built public UI", encoding="utf-8")
    return repository


@pytest.mark.parametrize("distribution", ["Ubuntu", "Debian", "Ubuntu-24.04"])
def test_template_uses_current_home_and_distribution(distribution):
    rendered = BOOTSTRAP.render_template(TEMPLATE.read_text(encoding="utf-8"), Path("/home/operator"), distribution)

    assert '"-d", "' + distribution + '"' in rendered
    assert "/home/operator/.local/bin/linux-mcp-server" in rendered
    assert "<wsl-user>" not in rendered
    assert 'LINUX_MCP_REQUIRE_MANAGED_HOST = "true"' in rendered
    assert 'LINUX_MCP_VERIFY_HOST_KEYS = "true"' in rendered


@pytest.mark.parametrize("distribution", ["bad\nname", "../Ubuntu", "", 'Ubuntu"'])
def test_template_rejects_unsafe_distribution(distribution):
    with pytest.raises(ValueError, match="发行版"):
        BOOTSTRAP.render_template(TEMPLATE.read_text(encoding="utf-8"), Path("/home/operator"), distribution)


@pytest.mark.parametrize("home", [Path("relative"), Path('/home/bad"name')])
def test_template_rejects_unsafe_home(home):
    with pytest.raises(ValueError, match="home"):
        BOOTSTRAP.render_template(TEMPLATE.read_text(encoding="utf-8"), home, "Ubuntu")


def test_template_rejects_incomplete_environment_forwarding():
    template = TEMPLATE.read_text(encoding="utf-8").replace("WSLENV =", "MISSING =")
    with pytest.raises(ValueError, match="WSLENV"):
        BOOTSTRAP.render_template(template, Path("/home/operator"), "Ubuntu")
    with pytest.raises(ValueError, match="配置段"):
        BOOTSTRAP.render_template("missing-sections", Path("/home/operator"), "Ubuntu")


def test_merge_preserves_unrelated_configuration_and_is_idempotent():
    unrelated = '[model]\nname = "keep"\n\n[mcp_servers.other]\ncommand = "other"\n'
    existing = unrelated + '\n[mcp_servers.linux-centos-ro]\ncommand = "old"\n'
    existing += '\n[mcp_servers.linux-centos-ro.env]\nOLD = "value"\n'
    rendered = BOOTSTRAP.render_template(TEMPLATE.read_text(encoding="utf-8"), Path("/home/operator"), "Debian")
    updated = BOOTSTRAP.merge_sections(existing, rendered)

    assert updated.startswith(unrelated)
    assert 'command = "old"' not in updated
    assert 'OLD = "value"' not in updated
    assert BOOTSTRAP.merge_sections(updated, rendered) == updated
    assert BOOTSTRAP.merge_sections("", rendered) == rendered


@pytest.mark.parametrize(
    "existing",
    [
        "[mcp_servers.linux-centos-ro]\n[mcp_servers.linux-centos-ro]\n",
        '[mcp_servers."linux-centos-ro"]\n',
        "[mcp_servers.linux-centos-ro.tools.read_file]\n",
        "[mcp_servers.linux-centos-ro] # custom\n",
    ],
)
def test_merge_refuses_ambiguous_existing_configuration(existing):
    with pytest.raises(ValueError):
        BOOTSTRAP.merge_sections(existing, "replacement")


def test_bootstrap_skip_install_only_updates_selected_config(source_repository, tmp_path, mocker):
    config = tmp_path / "codex" / "config.toml"
    execute = mocker.patch.object(BOOTSTRAP.subprocess, "run", autospec=True)

    BOOTSTRAP.bootstrap(source_repository, config, "Debian", install=False)

    assert config.is_file()
    assert not (source_repository / "config" / "centos-policy.local.json").exists()
    assert not (tmp_path / "hosts").exists()
    execute.assert_not_called()
    writer = mocker.patch.object(BOOTSTRAP, "write_atomic", autospec=True)
    BOOTSTRAP.bootstrap(source_repository, config, "Debian", install=False)
    writer.assert_not_called()


def test_install_failure_preserves_existing_config(source_repository, tmp_path, mocker):
    config = tmp_path / "config.toml"
    config.write_text('model = "keep"\n', encoding="utf-8")
    mocker.patch.object(BOOTSTRAP, "local_command", autospec=True, return_value="uv")
    mocker.patch.object(BOOTSTRAP.subprocess, "run", autospec=True, side_effect=subprocess.CalledProcessError(1, "uv"))

    with pytest.raises(subprocess.CalledProcessError):
        BOOTSTRAP.bootstrap(source_repository, config, "Ubuntu", install=True)

    assert config.read_text(encoding="utf-8") == 'model = "keep"\n'


def test_successful_install_checks_both_entrypoints(source_repository, tmp_path, mocker):
    config = tmp_path / "config.toml"
    mocker.patch.object(BOOTSTRAP, "local_command", autospec=True, side_effect=lambda name: name)
    execute = mocker.patch.object(BOOTSTRAP.subprocess, "run", autospec=True)

    BOOTSTRAP.bootstrap(source_repository, config, "Ubuntu", install=True)

    assert execute.call_count == 3
    assert execute.call_args_list[0].args[0] == [
        "uv",
        "tool",
        "install",
        "--reinstall",
        "--python",
        "3.11",
        str(source_repository),
    ]
    assert execute.call_args_list[1].args[0] == ["linux-mcp-server", "--version"]
    assert execute.call_args_list[2].args[0] == ["linux-mcp-hosts", "--help"]


def test_bootstrap_rejects_config_symlink_before_install(source_repository, tmp_path, mocker):
    target = tmp_path / "real-config"
    target.write_text("private", encoding="utf-8")
    config = tmp_path / "config.toml"
    config.symlink_to(target)
    execute = mocker.patch.object(BOOTSTRAP.subprocess, "run", autospec=True)

    with pytest.raises(ValueError):
        BOOTSTRAP.bootstrap(source_repository, config, "Ubuntu", install=True)

    assert target.read_text(encoding="utf-8") == "private"
    execute.assert_not_called()


def test_local_command_fallback_and_missing_command(tmp_path, mocker):
    mocker.patch.object(BOOTSTRAP.shutil, "which", autospec=True, return_value=None)
    mocker.patch.object(BOOTSTRAP.Path, "home", return_value=tmp_path)
    candidate = tmp_path / ".local" / "bin" / "uv"
    candidate.parent.mkdir(parents=True)
    candidate.write_text("#!/bin/sh\n", encoding="utf-8")
    candidate.chmod(0o700)

    assert BOOTSTRAP.local_command("uv") == str(candidate)
    with pytest.raises(ValueError, match="未找到"):
        BOOTSTRAP.local_command("missing-command")


def test_uninstall_archive_contains_only_public_script(tmp_path):
    source = tmp_path / "repo" / "scripts" / "centos" / "uninstall-readonly-account.sh"
    source.parent.mkdir(parents=True)
    source.write_text("#!/bin/bash\nprintf public-script\n", encoding="utf-8")
    (source.parent / "id_ed25519").write_text("PRIVATE MUST STAY LOCAL", encoding="utf-8")
    output = tmp_path / "bundles" / "uninstall.tar.gz"

    checksum = UNINSTALL.build_bundle(tmp_path / "repo", output)

    assert checksum == hashlib.sha256(output.read_bytes()).hexdigest()
    with tarfile.open(output) as archive:
        assert archive.getnames() == [source.name]
        content = archive.extractfile(source.name)
        assert content is not None
        assert content.read() == source.read_bytes()
    if os.name == "posix":
        assert output.stat().st_mode & 0o077 == 0
    original = output.read_bytes()
    with pytest.raises(ValueError, match="已存在"):
        UNINSTALL.build_bundle(tmp_path / "repo", output)
    assert output.read_bytes() == original


def test_uninstall_rejects_missing_or_symlinked_script(tmp_path):
    with pytest.raises(ValueError, match="缺少"):
        UNINSTALL.build_bundle(tmp_path, tmp_path / "bundle.tar.gz")
    source = tmp_path / "scripts" / "centos" / "uninstall-readonly-account.sh"
    source.parent.mkdir(parents=True)
    public_script = tmp_path / "public.sh"
    public_script.write_text("public", encoding="utf-8")
    source.symlink_to(public_script)
    with pytest.raises(ValueError, match="缺少"):
        UNINSTALL.build_bundle(tmp_path, tmp_path / "bundle.tar.gz")


def test_bootstrap_rejects_missing_source_or_unbuilt_ui(tmp_path):
    config = tmp_path / "config.toml"
    with pytest.raises(ValueError, match="源码目录"):
        BOOTSTRAP.bootstrap(tmp_path / "missing", config, "Ubuntu", install=False)
    with pytest.raises(ValueError, match="npm ci"):
        BOOTSTRAP.bootstrap(tmp_path, config, "Ubuntu", install=False)
    assert not config.exists()


def test_atomic_writer_rejects_symlink_parent(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError, match="符号链接"):
        BOOTSTRAP.write_atomic(linked / "config.toml", "private")
    assert not (actual / "config.toml").exists()


def test_local_command_uses_path_when_present(mocker):
    mocker.patch.object(BOOTSTRAP.shutil, "which", autospec=True, return_value="/usr/bin/uv")
    assert BOOTSTRAP.local_command("uv") == "/usr/bin/uv"


def test_merge_preserves_table_following_managed_sections():
    existing = '[mcp_servers.linux-centos-ro]\ncommand = "old"\n[other]\nvalue = "keep"\n'
    assert BOOTSTRAP.merge_sections(existing, "new\n") == '[other]\nvalue = "keep"\n\nnew\n'


def test_bootstrap_cli_rejects_relative_paths(mocker):
    mocker.patch.object(
        BOOTSTRAP.sys, "argv", ["bootstrap", "--repository", "relative", "--mcp-config", "/tmp/config.toml"]
    )
    assert BOOTSTRAP.main() == 1


def test_bootstrap_script_entrypoint_only_writes_temporary_config(source_repository, tmp_path, mocker):
    config = tmp_path / "config.toml"
    mocker.patch.object(
        BOOTSTRAP.sys,
        "argv",
        ["bootstrap", "--repository", str(source_repository), "--mcp-config", str(config), "--skip-install"],
    )
    with pytest.raises(SystemExit) as completed:
        runpy.run_path(str(SCRIPTS / "bootstrap_wsl_mcp.py"), run_name="__main__")
    assert completed.value.code == 0
    assert config.exists()


def test_uninstall_cli_rejects_invalid_source(tmp_path, mocker):
    mocker.patch.object(
        UNINSTALL.sys,
        "argv",
        ["uninstall", "--repository", str(tmp_path), "--output", str(tmp_path / "out.tar.gz")],
    )
    assert UNINSTALL.main() == 1


def test_uninstall_script_entrypoint_reports_checksum(tmp_path, mocker, capsys):
    source = tmp_path / "repo" / "scripts" / "centos" / "uninstall-readonly-account.sh"
    source.parent.mkdir(parents=True)
    source.write_text("public", encoding="utf-8")
    output = tmp_path / "out.tar.gz"
    mocker.patch.object(
        UNINSTALL.sys, "argv", ["uninstall", "--repository", str(tmp_path / "repo"), "--output", str(output)]
    )
    with pytest.raises(SystemExit) as completed:
        runpy.run_path(str(SCRIPTS / "prepare_uninstall.py"), run_name="__main__")
    assert completed.value.code == 0
    assert "sha256=" + hashlib.sha256(output.read_bytes()).hexdigest() in capsys.readouterr().out
