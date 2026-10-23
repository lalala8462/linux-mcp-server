# CentOS 兼容说明

项目总览见 [README](../README.md)，安装步骤见 [安装指南](windows-wsl-setup.md)，权限与方案取舍见 [使用与实现说明](centos-client-guide.md)。本文只列系统版本差异。

| 系统 | 命令兼容方式 | 需要接受的限制 |
| --- | --- | --- |
| CentOS 6 | 系统信息使用 procfs/传统 release 文件；服务列表可用 chkconfig；磁盘使用 df；网络可回退 netstat | 无 systemd/journalctl 时相关能力 unsupported；仅明确批准的主机使用 RSA 4096 与旧 ssh-rsa |
| CentOS 7 | 对 free、lsblk、findmnt、ip 的旧参数/输出提供兼容变体 | 部分设备关系或字段可能降级；以画像及实时结果为准 |
| CentOS 8 / Stream 8、9 | 优先现代命令与输出 | 缺少命令或权限时仍需降级；不是所有主机都保证 19 项 exact |

- 保持上游 MCP 工具名称和参数协议，能力由每台主机的 `exact`、`partial`、`unsupported` 矩阵表达。
- 画像 schema v2 批准 1..16 个互不重叠的 `allowed_roots`，兼容旧单根画像；旧画像默认为普通读取，不自动启用 root helper。
- MCP 包要求 Python >=3.10；远端包装器与固定读取 helper 兼容 Python 2.6/3.x。CentOS 7 也可能使用 Python 2.7，安装器按目标 `/usr/bin/python` 预检。
- root 读取通过精确 sudoers 调用固定 helper，不改变 SSH 身份、不开放通用命令；目录范围不自动扩大。新增 helper 必须随升级包完整安装并重新验收，不能只重发旧包装器。
- 远端 Python 2.6 文本、路径与安全打开的兼容处理，以及账号安装要求，见 [只读包装器部署](centos-readonly-overlay.md)。
- 新系统或工具版本应重新探测，不将某一台机器的验收结果推广为整个发行版已验证。
