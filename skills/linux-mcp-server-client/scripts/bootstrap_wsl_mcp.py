#!/usr/bin/env python3
# ruff: noqa: T201
"""在 WSL 安装指定源码，并只更新 Windows Codex 的受管 MCP 配置段。"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

from pathlib import Path


SECTIONS = ("[mcp_servers.linux-centos-ro]", "[mcp_servers.linux-centos-ro.env]")


def require_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"必须是普通文件：{path}")


def render_template(template: str, home: Path, distribution: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", distribution):
        raise ValueError("WSL 发行版名称无效")
    if not home.is_absolute() or any(value in str(home) for value in ('"', "\\", "\r", "\n")):
        raise ValueError("WSL home 路径无效")
    rendered = template.replace("/home/<wsl-user>", str(home)).replace("<wsl-user>", home.name)
    rendered = rendered.replace('"-d", "Ubuntu"', '"-d", ' + json.dumps(distribution))
    if "<wsl-user>" in rendered or not all(section in rendered for section in SECTIONS):
        raise ValueError("MCP 模板缺少配置段或包含未替换占位符")
    env = rendered.split(SECTIONS[1], 1)[1]
    names = set(re.findall(r"^([A-Z][A-Z0-9_]*)\s*=", env, re.MULTILINE)) - {"WSLENV"}
    match = re.search(r'^WSLENV\s*=\s*"([^"]+)"', env, re.MULTILINE)
    if match is None or set(match.group(1).split(":")) != names:
        raise ValueError("模板的 WSLENV 与 MCP 环境变量不一致")
    return rendered.rstrip() + "\n"


def merge_sections(existing: str, rendered: str) -> str:
    lines = existing.splitlines(keepends=True)
    spans: list[tuple[int, int]] = []
    seen: set[str] = set()
    for index, line in enumerate(lines):
        header = line.strip()
        # 不猜测带引号、行尾注释或未知嵌套表的含义，避免写入重复配置。
        if "mcp_servers" in header and "linux-centos-ro" in header and header.startswith("["):
            if header not in SECTIONS:
                raise ValueError("现有 linux-centos-ro 使用非标准表头，请先人工核对")
            if header in seen:
                raise ValueError("现有 linux-centos-ro 配置段重复")
            seen.add(header)
            end = next(
                (offset for offset in range(index + 1, len(lines)) if lines[offset].lstrip().startswith("[")),
                len(lines),
            )
            spans.append((index, end))
    for start, end in reversed(spans):
        del lines[start:end]
    retained = "".join(lines).rstrip("\r\n")
    return (retained + "\n\n" if retained else "") + rendered


def write_atomic(path: Path, content: str) -> None:
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("拒绝写入符号链接配置路径")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".linux-mcp-config-", dir=path.parent)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
    os.replace(name, path)


def local_command(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    candidate = Path.home() / ".local" / "bin" / name
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    raise ValueError(f"未找到本机命令：{name}")


def bootstrap(repository: Path, config: Path, distribution: str, *, install: bool) -> None:
    if repository.is_symlink() or not repository.is_dir():
        raise ValueError("源码目录不存在或是符号链接")
    repository = repository.resolve(strict=True)
    ui_asset = repository / "mcp-app" / "dist" / "run-script-app.html"
    if ui_asset.is_symlink() or not ui_asset.is_file():
        raise ValueError("缺少前端构建产物；请先在仓库 mcp-app 中运行 npm ci 和 npm run build:prod")
    template = repository / "config" / "codex-mcp-snippet.toml"
    require_file(template)
    if config.exists() or config.is_symlink():
        require_file(config)
        existing = config.read_text(encoding="utf-8")
    else:
        existing = ""
    rendered = render_template(template.read_text(encoding="utf-8"), Path.home(), distribution)
    updated = merge_sections(existing, rendered)
    if install:
        subprocess.run(
            [local_command("uv"), "tool", "install", "--reinstall", "--python", "3.11", str(repository)],
            check=True,
        )
        subprocess.run([local_command("linux-mcp-server"), "--version"], check=True)
        subprocess.run([local_command("linux-mcp-hosts"), "--help"], check=True, stdout=subprocess.DEVNULL)
    if updated != existing:
        write_atomic(config, updated)
    print(f"mcp_config={config}")
    print("仅更新 linux-centos-ro 主段和环境段；未创建主机、密钥或远端账号。")
    print("请新开 Codex 会话，并执行 codex mcp list 检查配置。")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True, help="WSL 内本 fork 的源码绝对路径")
    parser.add_argument("--mcp-config", type=Path, required=True, help="Windows Codex 配置映射到 WSL 的绝对路径")
    parser.add_argument("--distribution", default=os.environ.get("WSL_DISTRO_NAME", "Ubuntu"))
    parser.add_argument("--skip-install", action="store_true", help="仅生成配置，不安装工具")
    args = parser.parse_args()
    try:
        if not args.repository.is_absolute() or not args.mcp_config.is_absolute():
            raise ValueError("源码和配置必须使用绝对路径")
        bootstrap(args.repository, args.mcp_config, args.distribution, install=not args.skip_install)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"错误：{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
