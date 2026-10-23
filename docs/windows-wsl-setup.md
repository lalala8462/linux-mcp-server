# Windows / WSL 安装、配置与验证

[返回项目首页](../README.md) · [使用与实现说明](centos-client-guide.md)

本指南用于首次安装、升级客户端或搭建开发环境，包含完整命令与配置说明。仅查看项目用途和环境要求时，先读首页。

由 AI Agent 从零安装、WSL 或依赖尚未准备好时，先按 [Agent 安装指南](agent-setup.md) 检测并补齐环境，再执行本文命令。

## 1. 准备环境并克隆本 fork

控制端需要 Windows Codex、WSL（下文以 Ubuntu 为例），以及 WSL 内的 `git`、`uv`、OpenSSH 客户端、Node.js 22.12+ 与 npm。MCP 包要求 Python >=3.10，本安装脚本选择 Python 3.11 独立工具环境。`uv` 安装方式见 [Astral 官方文档](https://docs.astral.sh/uv/getting-started/installation/)。远端需要 SSH 服务、Bash，以及安装器调用的 `/usr/bin/python`（兼容 Python 2.6/3.x）；管理员须能执行安装步骤。

在 **WSL 终端**运行，将源码留在 WSL 原生文件系统：

```sh
mkdir -p ~/src
git clone --branch codex/centos7-compat-1.5.0 \
  https://github.com/lalala8462/linux-mcp-server.git ~/src/linux-mcp-server
cd ~/src/linux-mcp-server
git rev-parse HEAD
cd mcp-app
npm ci
npm run build:prod
cd ..
```

记录完整提交号用于复现。当前 Python 打包配置强制包含 `mcp-app/dist`，因此 fixed 模式也须先构建该前端资产；这不会启用脚本执行工具。不要用 `pip install linux-mcp-server` 或上游容器替代本 fork；不要长期从 `/mnt/c`、`/mnt/g` 等挂载盘运行生命周期命令。

## 2. 安装 client Skill 与 MCP 配置

在 **Windows PowerShell** 中执行；如实际发行版不同，修改 `$Distro`：

```powershell
$Distro = 'Ubuntu'
$WslHome = (wsl.exe -d $Distro -- sh -lc 'printf "%s" "$HOME"').Trim()
$RepoInWsl = "$WslHome/src/linux-mcp-server"
$SkillSource = (wsl.exe -d $Distro -- wslpath -w "$RepoInWsl/skills/linux-mcp-server-client").Trim()
$SkillParent = Join-Path $env:USERPROFILE '.agents\skills'
$SkillTarget = Join-Path $SkillParent 'linux-mcp-server-client'
if (Test-Path -LiteralPath $SkillTarget) { throw 'Skill 已存在，请先核对版本，不自动覆盖。' }
New-Item -ItemType Directory -Path $SkillParent -Force | Out-Null
Copy-Item -LiteralPath $SkillSource -Destination $SkillTarget -Recurse

$CodexDir = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE '.codex' }
$ConfigInWsl = (wsl.exe -d $Distro -- wslpath -u (Join-Path $CodexDir 'config.toml')).Trim()
wsl.exe -d $Distro -- python3 "$RepoInWsl/skills/linux-mcp-server-client/scripts/bootstrap_wsl_mcp.py" --repository $RepoInWsl --mcp-config $ConfigInWsl --distribution $Distro
```

当前官方用户 Skill 目录是 `~/.agents/skills`，参见 [OpenAI Skills 文档](https://learn.chatgpt.com/docs/build-skills)。已有客户端如使用 `~/.codex/skills`，按实际目录安装一次；不要在两个目录重复安装同名 Skill。

bootstrap 安装 `linux-mcp-server`、`linux-mcp-hosts`，将模板中的 WSL home 和发行版替换为当前机器值，并原子更新 Codex 的 `linux-centos-ro` 主段和环境段。它不读取其他人的配置，不创建主机、密钥或远端账号；非标准现有配置会停止并要求人工核对。

配置来源为 [codex-mcp-snippet.toml](../config/codex-mcp-snippet.toml)，关键项如下：

| 配置 | 本方案值或用途 |
| --- | --- |
| `command` / `args` | `wsl.exe` 启动当前 WSL 原生安装的 `linux-mcp-server` |
| `enabled_tools` | 19 个固定工具；不是安装器或卸载器 |
| `LINUX_MCP_TOOLSET` | `fixed` |
| `LINUX_MCP_REQUIRE_MANAGED_HOST` | `true`，强制注册表别名 |
| `LINUX_MCP_HOST_REGISTRY_PATH` | WSL `~/.local/share/linux-mcp-server/hosts` |
| `LINUX_MCP_VERIFY_HOST_KEYS` | `true` |
| `WSLENV` | 将 Windows MCP 环境变量传入 WSL，不可遗漏 |
| 读取量与超时 | 模板为文件最多 1 MiB、单命令 30 秒、工具调用 60 秒 |

模板中单主机密钥路径与通用目录是兼容占位；受管调用采用每台主机画像中的身份和根目录，不能将模板占位当作已登记服务器。手工配置时须保持上述边界，字段定义见 [OpenAI MCP 文档](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)。

新开 Codex 会话后检查。本机有 Codex CLI 时列出 MCP 配置；仅使用桌面客户端时在其 MCP 设置中确认连接：

```powershell
if (Get-Command codex -ErrorAction SilentlyContinue) { codex mcp list }
wsl.exe -d $Distro -- "$WslHome/.local/bin/linux-mcp-hosts" --help
wsl.exe -d $Distro -- "$WslHome/.local/bin/linux-mcp-hosts" list
```

`codex mcp list` 只证明配置存在；首次没有主机时列表为空是正常现象。接下来在 Codex 输入“使用 $linux-mcp-server-client 新增服务器”，提供该机器的 IPv4、端口和批准根目录。

## 3. 纳管并验收服务器

完整可执行命令见 [主机生命周期](../skills/linux-mcp-server-client/references/host-lifecycle.md)，顺序为：

1. `discover` 生成无密钥探测包，输出两种路径和 SHA256。
2. 管理员通过可信渠道上传、核验摘要、执行探测并回传 JSON 与主机公钥文件。
3. `import-profile` 绑定地址、端口、全部批准根目录和能力矩阵；每个根重复一个 `--allowed-root`，确认 partial/unsupported。
4. `prepare` 核对可信公钥后才生成独立客户端密钥和部署包；私钥留在 WSL。已明确接受受控 root 读取时加 `--read-mode privileged`，普通模式为 `user`。
5. 管理员核验部署包 SHA256，执行实际输出的 `install_command`。CentOS 6 与其他版本的公钥文件名和参数不同，不手工套用固定命令。
6. root 模式安装器在每个根创建 `.linux-mcp-verify` 非敏感样本：普通文本、root 专属文本/日志、0700 目录和根外符号链接。`verify` 经真实 MCP 调用 19 项能力及额外读取/拒绝检查，全部通过才记为已验收；无需先给样本补 ACL。

在日常会话中先列出注册表并选择别名，再将该别名作为每次 MCP 调用的 `host`。可请求“检查 server-a 的内存、磁盘与监听端口”或“读取 server-a 批准目录下应用日志的最近 100 行”。示例别名不是实际主机。

## 开发与验证

本节仅用于修改项目源码的开发者，普通使用者安装可跳过。安装是否成功以本机工具可用、客户端实际加载，以及目标服务器的真实验收为准。

```sh
uv sync --locked
make verify
```

`make verify` 执行依赖同步、Ruff、格式检查、Pyright 与完整单元测试。客户端脚本的测试在 [test_client_skill.py](../tests/test_client_skill.py)，覆盖配置保留、身份/路径可移植性、失败时不改配置及卸载包内容边界。测试使用临时文件和虚构数据，不要求连接生产服务器。

helper 的协议、路径与资源限制测试见 [test_privileged_read.py](../tests/test_privileged_read.py)，安装/升级与真实 MCP 验收逻辑由相关生命周期测试覆盖。root 模式不接受 `--results-json` 导入成功记录。

真实目标服务器是否可用，仍需管理员安装并完成该主机的 `verify`；本地 Python 兼容检查和隔离 sudo 测试不能代表某台生产服务器验收通过。开发者说明见 [contributing](contributing.md)，上游通用结构见 [architecture](architecture.md)。代码沿用仓库 [LICENSE](../LICENSE) 与随附许可证要求。
