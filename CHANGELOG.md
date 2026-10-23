# 更新记录

本文记录本 fork 的变更，完整提交记录见 [GitHub 历史](https://github.com/lalala8462/linux-mcp-server/commits/codex/centos7-compat-1.5.0/)。

## 未发布

- 将 README 调整为面向使用者的首页，保留架构图、能力与安全边界和环境要求。
- 将安装、配置、开发验证及使用细节拆分到独立文档，更新相关入口。
- 将版本优化记录移出首页，移除源码上传范围说明及发布检查清单。

## 2026-10-22 — 受控 root 读取与客户端整理

对应提交：[28da718](https://github.com/lalala8462/linux-mcp-server/commit/28da7186c894c8584d6231626838ef905f24cda9) 至 [a86819f](https://github.com/lalala8462/linux-mcp-server/commit/a86819ffd4ec8731fa4e2af545a2a0daf9f0b793)。

### 新增

- 增加显式 privileged 读取模式和专用 root helper，保持 codex-ro 登录及固定只读工具边界。
- 支持多批准根目录；升级包包含 helper、策略和摘要，复用已有账号、密钥及主机身份。
- 安装器生成非敏感验收样本，通过真实 MCP 检查能力、root 文件/目录读取和越界拒绝。
- 发布可移植的 client Skill、客户端安装脚本及公开配置模板。

### 调整

- Skill 保留简短入口，安装与主机生命周期按需读取；主机注册表作为唯一事实来源。
- 不再分发旧的一阶段预配与 SSH 别名管理路径，密钥和部署材料统一由 CLI 管理。
- 主机列表集中展示目标、读取模式和状态，使用 CLI 实际输出的安装命令。
- 卸载不自动重新纳管，单机退役不移除共享 MCP；静态文档审查不要求选择远端。
- 合并重复总览，清理误导为上游发布物的徽章和 Registry 标记。

### 修复

- 安装器区分本工具的精确 helper 授权与宽泛 sudo 权限。
- 兼容 sudo 1.8.6p3 无授权查询仍返回 0 的情况，未知查询错误继续拒绝。
- 验收器要求明确的越界拒绝原因，避免将路径回显、权限错误或连接失败计作通过。
- 解码文件工具的中文 stderr，保证远端拒绝原因正确传递。
- 禁止 root helper 写入 Python 字节码缓存。
