# 客户端安装与升级

仅在首次安装、工具缺失或用户要求升级时读取。发行版、用户名和源码路径均取自当前机器，不复制他人的个人配置。

源码为 [lalala8462/linux-mcp-server](https://github.com/lalala8462/linux-mcp-server)，分支 `codex/centos7-compat-1.5.0`；完整前置安装步骤见 [安装指南](https://github.com/lalala8462/linux-mcp-server/blob/codex/centos7-compat-1.5.0/docs/windows-wsl-setup.md)。先查找用户已指定的克隆目录；缺少源码时按该入口安装，不从上游 PyPI 包推断已具备本 fork 能力。

Windows 运行 Codex，WSL 运行 MCP。WSL 需要 `git`、`uv`、OpenSSH 客户端及用于源码构建的 Node.js/npm；bootstrap 使用 `uv` 安装 Python 3.11 独立工具环境，远端 Python 不受此要求影响。先按安装指南在 `mcp-app` 执行 `npm ci` 与 `npm run build:prod`；当前打包配置强制包含构建产物，即使 fixed 模式也须完成此步。bootstrap 不下载或执行任意远端脚本，缺少产物时停止。

仓库克隆到 WSL 原生文件系统，如 `~/src/linux-mcp-server`。必须显式传入路径：

```sh
python3 <skill-dir>/scripts/bootstrap_wsl_mcp.py \
  --repository <WSL源码绝对路径> \
  --mcp-config <Windows配置映射后的绝对路径> \
  --distribution <WSL发行版>
```

脚本仅更新 `[mcp_servers.linux-centos-ro]` 及 `.env`；保留其他配置，不创建主机或密钥。已有非标准表头或自定义嵌套表时停止，先核对用户定制。`--skip-install` 仅生成配置，不能据此认定工具已安装。

复制整个 `skills/linux-mcp-server-client` 到客户端支持的用户 Skill 目录。当前官方目录是 `~/.agents/skills`，已有客户端可能使用 `~/.codex/skills`；不要安装两份同名副本。仅复制公开 Skill 文件，不复制 `.codex` 或 WSL 数据目录。Skill 本身不包含 MCP 二进制，仍须执行 bootstrap。

核对仓库 `config/codex-mcp-snippet.toml`：

- `LINUX_MCP_TOOLSET=fixed`；`enabled_tools` 仅含 19 个接口。
- `LINUX_MCP_REQUIRE_MANAGED_HOST=true`，注册表在原生 WSL 文件系统。
- `LINUX_MCP_VERIFY_HOST_KEYS=true`；不全局放开旧 SSH 算法。
- `WSLENV` 覆盖全部模板环境变量，否则 Windows 值不能完整传给 WSL。
- 实际主机使用独立画像中的密钥、known_hosts、allowed_roots 与 read_mode；模板中的兼容路径不证明主机已纳管。root helper 仅由管理员通过部署包安装，不由 bootstrap 远端执行。

新开 Codex 会话，执行 `codex mcp list` 检查配置；该命令不证明远端已安装。`linux-mcp-hosts --help` 检查本机工具，生命周期 `verify` 检查指定主机，不为核对配置连接任意远端。

升级前确认分支与提交并保留本地改动；不要直接发布脏工作区。重新执行 bootstrap，必要时通过 `rebuild-deployment` 更新远端包装器并重新验收。Skill 文件升级与 MCP 工具重装是独立步骤。
