# 交给 AI Agent 的安装流程

[返回首页](../README.md) · [完整安装命令](windows-wsl-setup.md) · [主机生命周期](../skills/linux-mcp-server-client/references/host-lifecycle.md)

本指南供具备本机终端、文件和网络访问能力的 Agent 执行。安装目标是 **Windows Codex + WSL 内的 MCP**；执行安装的 Agent 可以来自其他产品，但本仓库不会自动生成其他 MCP 客户端的配置。用户登录、Windows 管理员操作、必要的重启及远端首次安装可能需要用户接手。

只收到仓库地址时，先阅读 README、本文及安装指南，再按下列阶段推进。已有主机和配置可以复用；不要重置 WSL、清空配置、覆盖其他项目的源码或重新生成已有密钥。

## 先确定输入与执行范围

| 输入 | 获取方式 |
| --- | --- |
| 目标客户端 | 确认用户使用 Windows Codex；其他客户端需要单独适配配置 |
| WSL 发行版、用户与 home | 从当前机器检测；有多个可用发行版时请用户选择，不套用维护者路径 |
| 源码目录 | 优先检查用户指定目录；新安装使用 WSL 原生文件系统，避免长期在 `/mnt/c` 等挂载盘运行 |
| Windows Codex 配置路径 | 按实际客户端确定；默认 Windows 用户目录下 `.codex/config.toml`，设置了 `CODEX_HOME` 时使用其位置，不误写 WSL 用户配置 |
| Skill 目录 | 按当前客户端确定，避免在 `.agents/skills` 与旧 `.codex/skills` 重复安装同名 Skill |
| 服务器参数 | 纳管前收集地址、端口、别名、1..16 个互不重叠且非 `/` 的批准根目录，以及 `user` 或 `privileged` 读取模式 |
| 主机身份与管理员交接渠道 | 由管理员经可信渠道提供完整主机公钥及探测结果；不使用网络扫描代替身份确认 |

用户只要求安装本机时，可以先完成前三个阶段，不为等待服务器参数而阻塞本机安装。缺少目标主机或批准范围时，不连接猜测的地址。

## 阶段 1：检查并补齐本机环境

### 1.1 Windows 与 WSL

在 Windows PowerShell 中探测，逐条检查结果：

```powershell
[Environment]::OSVersion.Version
Get-Command wsl.exe -ErrorAction SilentlyContinue
wsl.exe --status
wsl.exe --list --verbose
Get-Command codex -ErrorAction SilentlyContinue
```

WSL 尚未安装或没有可用发行版时，按 [Microsoft 安装说明](https://learn.microsoft.com/en-us/windows/wsl/install) 处理。下面命令需要相应管理员权限；已有可用发行版时不要重复安装：

```powershell
wsl.exe --install -d Ubuntu
```

如需重启、启用虚拟化或首次创建 Linux 用户，让用户通过本机界面完成并保留当前进度，完成后从本阶段重新检测。不要自动重启、注销现有发行版或收集用户密码。

`codex` 命令不存在，不等于桌面客户端没有安装。确认实际客户端及登录状态；缺少客户端或尚未登录时由用户先完成。后续命令中的 `$Distro` 必须使用检测到的真实发行版名称：

```powershell
$Distro = 'Ubuntu'
wsl.exe -d $Distro -- sh -lc 'id -un; id -u; printf "%s\n" "$HOME"; cat /etc/os-release'
```

当前模板使用该发行版的默认用户启动 MCP，必须确认默认用户是普通用户。默认用户为 root 时，先由用户设置为已经初始化的普通用户并重新检测；仅在安装命令中临时切换用户不能解决后续启动身份问题。每次执行 WSL、git、npm、uv 等外部命令后检查退出码；在 PowerShell 中用 `$LASTEXITCODE`，不要只依靠 `$ErrorActionPreference` 判断外部命令成功。

### 1.2 WSL 基础依赖

在所选 WSL 的 Bash 会话检查；这些依赖安装在 WSL 中：

```bash
for tool in git curl python3 ssh tar sha256sum; do
  command -v "$tool" || true
done
command -v uv || test -x "$HOME/.local/bin/uv"
command -v node || true
command -v npm || true
```

只补缺失依赖。下面列出 Ubuntu/Debian 所需的基础包，执行时根据检测结果仅保留缺失项；其他发行版使用其包管理器，不照搬 apt 命令：

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git openssh-client python3 tar xz-utils
```

若 sudo 需要交互，让用户在自己的终端输入，不索取或保存密码。不要执行整机升级，也不要用 `sudo pip` 修改系统 Python。

uv 缺失时按 [uv 官方安装说明](https://docs.astral.sh/uv/getting-started/installation/) 安装；下载到新临时目录后再执行，保留安装材料便于排错：

```bash
uv_install_dir="$(mktemp -d)"
curl -fsSL https://astral.sh/uv/install.sh -o "$uv_install_dir/install-uv.sh"
sh "$uv_install_dir/install-uv.sh"
export PATH="$HOME/.local/bin:$PATH"
uv --version
uv python install 3.11
```

已有可用 uv 时跳过安装器，只检查版本和 Python 3.11 是否可用。uv 管理的 Python 与远端解释器无关，见 [uv Python 说明](https://docs.astral.sh/uv/guides/install-python/)。

### 1.3 Node.js 与 npm

前端资源构建需要 Node.js 22.12+ 和 npm。先检查是否已安装；如果通过 nvm 安装，需要先在当前 Bash 会话加载其 `nvm.sh`。已有版本符合要求时直接复用。

缺失或版本过低时，可按 [Node.js 下载说明](https://nodejs.org/en/download) 与 [nvm 安装说明](https://github.com/nvm-sh/nvm#installing-and-updating) 使用用户级 nvm。若已经有 nvm，只执行加载和安装 Node.js 的步骤：

```bash
nvm_install_dir="$(mktemp -d)"
curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.8/install.sh -o "$nvm_install_dir/install-nvm.sh"
bash "$nvm_install_dir/install-nvm.sh"
```

按本机已有配置确定 `NVM_DIR`；未自定义时使用 nvm 的默认位置：

```bash
if [ -z "${NVM_DIR:-}" ]; then
  export NVM_DIR="${XDG_CONFIG_HOME:-$HOME}/.nvm"
  if [ -n "${XDG_CONFIG_HOME:-}" ]; then export NVM_DIR="$XDG_CONFIG_HOME/nvm"; fi
fi
. "$NVM_DIR/nvm.sh"
nvm install 22
nvm use 22
node --version
npm --version
node -e 'const [major, minor] = process.versions.node.split(".").map(Number); if (major < 22 || (major === 22 && minor < 12)) process.exit(1)'
```

这里选择 Node.js 22 系列并记录实际补丁版本，不额外改写现有 nvm 默认别名或其他项目的版本文件。新装 nvm 对本用户 shell 加载配置的变化也需记录。非交互 shell 不一定加载 nvm，后续构建必须在已经加载 Node 的会话中执行。网络失败时检查用户现有代理、证书和访问限制，不自行换不可信镜像或关闭 TLS 校验。

**本阶段完成条件**：WSL 普通用户可用，基础工具、uv、Python 3.11、满足要求的 Node.js 和 npm 均已确认。否则明确报告缺项及需要用户完成的操作，不能进入构建阶段。

## 阶段 2：安装本机 MCP、Skill 与配置

1. 按 [安装指南第 1 节](windows-wsl-setup.md#1-准备环境并克隆本-fork) 获取本 fork 并构建前端资源。源码分支为 `codex/centos7-compat-1.5.0`，记录 `git rev-parse HEAD`；已有目录先检查 remote、分支和未提交改动，不通过 reset、清空目录或覆盖文件来复用路径。
2. 确认 `mcp-app/dist/run-script-app.html` 已生成，再按 [第 2 节](windows-wsl-setup.md#2-安装-client-skill-与-mcp-配置) 安装 Skill 和运行 bootstrap。不要用同名上游 PyPI 包替代本 fork。
3. 使用当前 Windows 用户和 WSL home 转换路径。已有 Codex 配置先保留一份本机备份；bootstrap 只更新本工具的主段和 env 段，不能用配置模板替换整个文件。
4. Skill 目录已存在时先比对：相同则跳过复制；不同则核对用户修改后再升级。不要不加判断地重跑会拒绝已有目录的示例，也不要覆盖用户定制。
5. 逐条确认命令成功。已有非标准配置导致 bootstrap 拒绝时，保留错误和现有配置，由用户或 Agent 审查具体差异后处理，不通过删除配置绕过检查。

本机工具检查，在实际 WSL 普通用户下运行：

```bash
"$HOME/.local/bin/linux-mcp-server" --version
"$HOME/.local/bin/linux-mcp-hosts" --help
"$HOME/.local/bin/linux-mcp-hosts" list
```

**本阶段完成条件**：工具可运行、Skill 文件已安装、正确的 Windows Codex 配置已生成，启动路径没有 `<wsl-user>` 等未替换占位符，配置保留原有其他段。模板中的兼容目录和单主机密钥路径不代表真实主机授权，由受管画像覆盖，不因这些兼容路径尚不存在就关闭受管限制。主机列表为空可以是正常的首次安装状态；此时只能报告“本机安装完成”。

## 阶段 3：确认客户端已加载

按当前客户端的加载方式刷新 MCP 或新开 Codex 会话。Codex CLI 可用时检查 `codex mcp list`；桌面客户端使用其 MCP 设置检查连接状态。配置文件中存在一个服务器条目不能证明连接成功。

确认客户端实际能列出 `linux-centos-ro` 的 19 个固定工具，并能发现 `linux-mcp-server-client` Skill。没有主机时不为测试连接而调用随机地址。工具数量或名称不符时核对 `fixed`、`enabled_tools`、`WSLENV` 和受管主机要求等配置，见 [配置说明](windows-wsl-setup.md#2-安装-client-skill-与-mcp-配置)。

当前 Agent 无法刷新或观察目标客户端时，保留“本机已安装、待客户端加载”的状态，给出用户操作和继续入口。客户端与 Skill 的路径、加载说明参见 [OpenAI MCP 文档](https://learn.chatgpt.com/docs/extend/mcp) 和 [Skills 文档](https://learn.chatgpt.com/docs/build-skills)。

## 阶段 4：服务器探测、管理员安装与真实验收

按 [主机生命周期](../skills/linux-mcp-server-client/references/host-lifecycle.md) 连续执行以下流程，不另写通用远程安装通道：

| 步骤 | Agent 执行 | 管理员交接 / 完成条件 |
| --- | --- | --- |
| 收集参数 | 确认主机地址、端口、别名、批准根目录和读取模式 | 信息缺失先询问；根目录与 root 读取范围不得自动扩大 |
| discover | 生成无密钥探测包 | 交付 WSL/Windows 路径、SHA256 和完整命令，管理员上传并执行 |
| import-profile | 导入管理员回传的探测 JSON、探测包和目标信息 | 获取可信完整主机公钥；明确确认 partial/unsupported 或旧 RSA 例外 |
| prepare | 确认身份后生成独立密钥及部署包 | 提供包路径、SHA256、指纹和 CLI 实际输出的完整安装命令；私钥留本机 |
| 远端安装 | 等待并检查管理员返回的实际安装结果 | 当前 MCP 和强制只读 SSH 入口不能上传或安装，不收集 root 密码 |
| verify | 用更新后的 MCP 实际调用 19 项能力及对应读取检查 | root 模式使用安装样本；全部符合画像才登记 verified，失败不伪装为成功或 unsupported |

远端还必须满足 SSH、Bash、可用的 `/usr/bin/python` 及所选读取模式的依赖。安装器会预检解释器、sudoers 和路径权限；失败时保留输出定位问题，不由 Agent 在只读连接上安装软件、放开 sudo 或切换 root 登录。

已有受管服务器用 `rebuild-deployment` 增量出包，保留账号、密钥、主机身份和批准根，再经管理员安装与真实验收。不要删账号重新纳管；也不能只因部署包生成成功就标记远端已升级。

## 最终输出与成功判定

| 状态 | 必须有的证据 |
| --- | --- |
| 本机安装完成 | 实际发行版、用户、源码路径与提交、工具版本、Skill 路径和配置路径 |
| 客户端已就绪 | 客户端实际加载的 19 个工具和 Skill；未观察到时明确写待确认 |
| 待管理员安装 | 目标别名、批准根、读取模式、包的两种路径、SHA256、指纹和完整管理员命令 |
| 服务器已验收 | 每台自己的真实 verify 结果与时间，保留 partial/unsupported 和失败原因 |

若缺少前提或用户操作，报告“已完成哪些阶段、等待什么、从哪里继续”，不把整套部署统一报成功。实际主机信息、画像、密钥、配置备份、部署包和运行日志保留在本机，不写入公共仓库。

普通使用者安装**不需要运行 `make verify`**；它属于修改项目源码时的开发检查，不能用来代替客户端加载或服务器验收。
