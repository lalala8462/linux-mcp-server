# CentOS 客户端使用与实现说明

[返回项目首页](../README.md) · [安装、配置与验证](windows-wsl-setup.md)

本文说明组件职责、读取权限、维护流程与方案取舍。日常操作以主机注册表为准，具体命令见 [主机生命周期](../skills/linux-mcp-server-client/references/host-lifecycle.md)。

## 组件与源码入口

| 层次 | 职责 | 源码入口 |
| --- | --- | --- |
| client Skill | 选择主机、组织诊断、控制确认节点与管理员交接 | [SKILL.md](../skills/linux-mcp-server-client/SKILL.md) |
| 本机安装脚本 | 安装 WSL 工具、生成当前机器的 Codex MCP 配置 | [bootstrap_wsl_mcp.py](../skills/linux-mcp-server-client/scripts/bootstrap_wsl_mcp.py) |
| 主机生命周期 CLI | discover、import-profile、prepare、verify、refresh、rebuild-deployment | [manage_linux_hosts.py](../scripts/manage_linux_hosts.py) |
| MCP 工具与 SSH | 参数校验、能力选择、连接复用、格式化输出 | [tools](../src/linux_mcp_server/tools)、[ssh.py](../src/linux_mcp_server/connection/ssh.py) |
| 主机注册表 | 将别名绑定到地址、端口、身份、批准根目录和能力画像 | [host_registry.py](../src/linux_mcp_server/host_registry.py) |
| 远端包装器与安装器 | 强制命令、参数白名单、文件边界与专用账号检查 | [scripts/centos](../scripts/centos) |
| root 读取 helper | 固定 JSON 请求、root 管理策略、描述符校验和资源限制 | [linux-mcp-privileged-read](../scripts/centos/linux-mcp-privileged-read) |

`linux-centos-ro` 是客户端 MCP 配置名；`linux-mcp-hosts` 是本机 CLI；`server-a` 等才是传给 MCP 的 `host`。受管模式通过注册表确定连接信息，不依赖 `~/.ssh/config` 中存在同名别名。

## 读取模式与权限机制

- 使用 `fixed` 工具集，并在客户端列出 19 项工具白名单；不启用上游支持的 `run_script`/`both` 模式。
- `LINUX_MCP_REQUIRE_MANAGED_HOST=true` 拒绝遗漏 `host`、未登记主机和非受管工具，不能把裸 IP 当作绕过注册表的捷径。
- 每台主机的密钥和 known_hosts 独立，主机公钥由管理员通过可信渠道提供；不将 `ssh-keyscan` 作为身份依据。
- 远端账号为 `codex-ro`，密码锁定，公钥认证被强制交给包装器。系统操作仍以该账号执行；受控 root 读取模式仅调用一个固定 helper，不开放 root SSH 登录。
- 读取模式 `user` 保留普通 POSIX/ACL 语义；`privileged` 由 helper 在 root 身份下读取批准范围内的普通文件、日志和目录元数据。只读约束操作行为，路径批准本身不会授予 Linux 文件权限。
- helper 不新增常驻服务或端口，只接收有长度上限的标准输入 JSON，不接收任意命令。它按 root 管理策略逐层安全打开，再验证最终文件描述符；拒绝特殊文件、路径替换、越界和硬链接文件，并限制字节、行数和运行时间。
- 安装器拒绝宽泛 sudo，只接受本工具精确 helper 授权；helper 为 root:root 0700，策略及父目录由 root 控制，sudoers 为 0440。普通用户不能直接执行或修改 helper。
- `readOnlyHint` 是工具声明，实际限制依靠账号权限、强制命令与策略；仅安装 Skill 或设置客户端工具列表不足以建立远端边界。

画像 schema v2 支持每台服务器 **1..16 个非 `/`、互不重叠的 `allowed_roots`**；旧 schema v1 单根画像仍可读取并迁移，缺少 `read_mode` 时维持 `user`，不会自动获得 root 读取。系统信息等固定查询还会访问包装器允许的系统路径；业务根目录并不是对所有系统工具的全局文件沙箱。

选择 `privileged` 会扩大批准目录内的实际可见内容，必须先明确根目录范围；不得自动扩大根。ACL/读取组仍可用于普通权限管理，但 root 文件不必逐个补 ACL。root 或拥有完整 sudo 的管理员能够修改这些规则；共享 `codex-ro` 或其私钥的人不能被识别为不同调用者。

专用 sudoers 的核心规则如下，空字符串表示不允许命令行参数，语义见 [sudo 官方源码手册](https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in)：

```sudoers
Defaults:codex-ro !requiretty
codex-ro ALL=(root) NOPASSWD: /usr/local/libexec/linux-mcp-privileged-read ""
```

helper 还会检查内核记录的父进程 UID 与调用身份，兼容 sudo 的监护进程和直接 exec 模式，不只信任环境变量或 JSON 参数。目标 sudo 版本由安装器 `visudo` 和权限查询检查，不支持时停止，不退回通用 sudo 授权。批准根路径不能包含符号链接；硬链接文件也会被明确拒绝。

## 系统兼容与能力状态

| 系统 | SSH 身份策略 | 兼容限制 |
| --- | --- | --- |
| CentOS 6 | 明确批准后使用 RSA 4096；旧 `ssh-rsa` 例外仅限该主机 | 缺少 systemd/journalctl 的能力可能 unsupported；部分工具退回 procfs、chkconfig、df、netstat |
| CentOS 7 | Ed25519 | 旧 free、lsblk、findmnt、ip 等需要兼容输出解析 |
| CentOS 8 / Stream 8、9 | Ed25519 | 以实际软件与权限探测结果为准；画像当前只接受 CentOS major 6、7、8、9 |

`exact` 表示能力与预期一致，`partial` 表示明确降级，`unsupported` 表示不支持并返回可识别错误。CentOS Stream 10、任意 Linux 发行版和所有补丁版本均不在此表的承诺范围；支持的 major 也不等于每项工具都在真实机器验证过。

## 维护、权限与退役

- 升级前核对分支与提交，保留未提交改动；从审查过的源码重跑 bootstrap。复制 Skill 与重装 MCP 是独立动作，不会自动同步。旧 SSH 配置不作为现代受管连接的事实来源。
- 包装器/安装器更新后用 `rebuild-deployment` 复用密钥生成新包，管理员安装后重新验收；不要手工重组部署包。
- OS、主机公钥或能力变化后重新探测，通过 `refresh` 展示差异，确认后才接受并重新准备。
- 已纳管主机升级 root 读取，用 `rebuild-deployment --alias server-a --read-mode privileged --output <新包.tar.gz>`。复用原账号、密钥和主机身份，保留原 allowed_roots；管理员增量安装后再 `verify --alias server-a`，不删除账号重新纳管。生成新包会使原 verified 状态失效。
- 普通模式权限失败请管理员检查 `namei -l`、`stat`、`id codex-ro`、`getfacl`。稳定读取 root 文件采用明确批准的 helper 模式；helper 失败时核对模式、策略、专用 sudoers 和解释器，不将权限错误伪装为成功、空日志或 unsupported。
- 远端安装器仍使用 `/usr/bin/python`，不按 CentOS 大版本猜测 Python 版本。升级包必须同时包含 helper、包装器、安装器、策略、公钥与摘要清单；只重发旧包装器不会获得 helper 能力。
- 卸载由本机生成仅含公开卸载脚本的包，管理员执行 `--confirm-account codex-ro`。卸载不自动重新纳管，本机材料另行按明确授权处理。
- 单台退役保留其他主机与共享 MCP 配置；全部主机退役并得到授权后才移除共享入口。管理员脚本保留历史备份，本机清理使用回收站/Trash。
- `wsl --shutdown` 后现有 MCP transport 失效，新开会话。挂载盘 I/O 卡顿时避免重复启动进程，恢复后使用原生 WSL CLI。

远端安装器的账号检查、受管标记和备份行为见 [管理员部署细节](centos-readonly-overlay.md)。

## 优点与代价

| 方面 | 优点 | 代价或限制 |
| --- | --- | --- |
| 安全控制 | 客户端白名单、受管身份、远端强制命令和系统权限构成多层限制 | Skill 是行为约定，需配合真实部署；只读仍会暴露批准范围内的数据 |
| root 文件 | 固定 helper 补充目录内读取权限，日志重建不再依赖逐文件 ACL | 增加了受控 root 代码的维护成本；批准范围内的 root 数据会变得可见，必须审查范围 |
| 旧系统兼容 | 远端不需要现代 Python MCP 环境，按能力选择兼容命令 | CentOS 6 的旧 RSA 算法与缺失工具需要显式接受，不能补齐不存在的服务语义 |
| 多主机 | 一个 MCP 入口，多份独立身份与画像，未知别名默认拒绝 | 本机需保护注册表与无交互使用的私钥，管理规模扩大后需要轮换与集中治理 |
| 权限分工 | AI 只诊断，管理员审核执行部署和卸载 | 首次纳管需多次交接；文件权限与轮转配置仍须管理员维护 |
| 可验证性 | 19 项能力矩阵、稳定降级标记和逐主机验收 | 静态单元测试、画像声明与真实远端验收各有范围，不能互相代替 |
| 性能 | SSH 连接复用、命令超时和读取量限制 | 目录大小排序可能扫描大树；`top_n` 限制返回条数，不保证只扫描少量文件 |
| 数据治理 | 密钥和部署状态留本机，部署包不含私钥 | 日志可能记录地址、别名、路径和命令；返回文件/日志会进入 AI 会话上下文，不是离线数据隔离方案 |
| 部署 | WSL 原生安装避开长期挂载盘执行问题 | 依赖 Windows/WSL 生命周期，WSL 重启后需重建 MCP 连接 |

当前默认审计日志位于 WSL `~/.local/share/linux-mcp-server/logs`，默认保留轮转数量为 10；这不是“绝不记录服务器信息”的保证。目录、进程参数及日志内容都应按组织的数据规则控制。
