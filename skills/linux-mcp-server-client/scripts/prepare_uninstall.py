#!/usr/bin/env python3
# ruff: noqa: T201
"""仅打包公开卸载脚本，不读取主机注册表、密钥或 SSH 配置。"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tarfile

from pathlib import Path


def build_bundle(repository: Path, output: Path) -> str:
    source = repository / "scripts" / "centos" / "uninstall-readonly-account.sh"
    if source.is_symlink() or not source.is_file():
        raise ValueError("仓库中缺少普通卸载脚本")
    if output.is_symlink() or output.exists() or output.parent.is_symlink():
        raise ValueError("输出已存在或输出路径不安全")
    output.parent.mkdir(parents=True, exist_ok=True)
    # 排他创建，拒绝覆盖；包内仅包含这一份公开脚本。
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream, tarfile.open(fileobj=stream, mode="w:gz") as archive:
        archive.add(source, arcname=source.name, recursive=False)
    return hashlib.sha256(output.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        digest = build_bundle(args.repository, args.output)
    except (OSError, ValueError) as error:
        print(f"错误：{error}", file=sys.stderr)
        return 1
    print(f"uninstall_bundle={args.output.resolve()}")
    print(f"sha256={digest}")
    print("未连接远端；仅在用户确认目标后，由管理员核对摘要并执行卸载脚本。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
