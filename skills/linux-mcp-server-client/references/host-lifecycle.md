# 受管主机生命周期

示例在 WSL 内执行；`linux-mcp-hosts` 不在 PATH 时用 `~/.local/bin/linux-mcp-hosts`。`server-a`、`192.0.2.10`、`/opt/example-app` 均为占位数据。实际值来自用户批准。

## 探测与导入

收集 IPv4、端口（默认 22）、读取模式与 1..16 个非 `/` 且互不重叠的批准根目录；默认别名为 IPv4，用户可另指定。root 模式扩大目录内可见内容，范围必须明确且不得自动扩大；根路径及其父路径不能是符号链接。

```sh
linux-mcp-hosts discover --alias server-a \
  --allowed-root /opt/example-app \
  --allowed-root /var/log/example-app \
  --output-dir ~/.local/share/linux-mcp-server/bundles
```

交付包的 WSL/Windows 路径和 SHA256。管理员默认上传至 `/data/server-a-discovery.tar.gz`；将下方摘要替换为本次输出：

```sh
set -eu
BUNDLE='/data/server-a-discovery.tar.gz'
EXPECTED_SHA256='<本次探测包SHA256>'
WORK_DIR="$(mktemp -d /var/tmp/linux-mcp-discovery.XXXXXX)"
printf '%s  %s\n' "$EXPECTED_SHA256" "$BUNDLE" | sha256sum -c -
tar -xzf "$BUNDLE" -C "$WORK_DIR"
cd "$WORK_DIR/server-a-discovery"
sh ./run-discovery.sh
ls -l ./discovery-result.json
```

管理员经可信渠道回传 JSON 及其中列出的完整主机公钥文件。包不含密钥；回传画像与公钥身份材料不可上传公开仓库。

```sh
linux-mcp-hosts import-profile --alias server-a \
  --address 192.0.2.10 --port 22 \
  --allowed-root /opt/example-app \
  --allowed-root /var/log/example-app \
  --discovery-json /path/to/discovery-result.json \
  --bundle ~/.local/share/linux-mcp-server/bundles/server-a-discovery.tar.gz
```

展示全部 19 项 `exact` / `partial` / `unsupported`。后两者需要明确确认；画像中的支持不等于实时验收通过。

## 准备与管理员安装

```sh
linux-mcp-hosts prepare --alias server-a \
  --trusted-host-key-file /path/to/trusted-host-key.pub \
  --read-mode privileged \
  --output-dir ~/.local/share/linux-mcp-server/bundles
```

上例采用已经确认的受控 root 读取；普通权限模式改用 `--read-mode user`（旧画像默认值）。仅接受不完整能力后添加 `--accept-incomplete`；CentOS 6 还须明确批准后添加 `--allow-rsa`。不能假设 CentOS 7 都有 Python 3；安装器必须用目标 `/usr/bin/python` 通过包装器/helper 预检。

交付两种包路径、SHA256、指纹和 CLI 输出的完整 `install_command`。管理员默认上传至 `/data/server-a-deployment.tar.gz` 并核验：

```sh
set -eu
BUNDLE='/data/server-a-deployment.tar.gz'
EXPECTED_SHA256='<本次部署包SHA256>'
WORK_DIR="$(mktemp -d /var/tmp/linux-mcp-deployment.XXXXXX)"
printf '%s  %s\n' "$EXPECTED_SHA256" "$BUNDLE" | sha256sum -c -
tar -xzf "$BUNDLE" -C "$WORK_DIR"
cd "$WORK_DIR/server-a-deployment"
cat ./INSTALL.txt
```

实际交付时用本次完整 `install_command` 替换最后一行，不能只让管理员猜测。CentOS 6 使用 `id_rsa.pub --allow-rsa`，其他版本使用 `id_ed25519.pub`。仅核对过的旧账号缺少受管标记时增加 `--adopt-existing`。

## 验收与维护

管理员安装时会为每个根创建 `.linux-mcp-verify` 非敏感样本：普通文本、root:root 0600 文本/日志、0700 目录和指向根外的链接。root 模式直接运行：

```sh
linux-mcp-hosts verify --alias server-a
```

它通过实际 MCP 调用全部 19 项，再检查每个根的 root 文本、日志、目录/文件列表、目录大小和越界拒绝。只有全部通过才写 verified，不依赖逐文件 ACL。普通模式仍需管理员确认样本可读并逐根提供文本，例如：

```sh
linux-mcp-hosts verify --alias server-a \
  --sample-file /opt/example-app/health.txt \
  --sample-file /var/log/example-app/health.txt \
  --sample-log-file /opt/example-app/logs/app.log
```

exact 成功、partial 带标记、unsupported 返回稳定错误，权限失败不得归为后两者。验收记录仅保存归一化状态；普通审计日志仍可能记录别名、路径等元数据。root 模式拒绝 `--results-json`，不接受人工构造成功结果；工具验收的目录扫描只在样本树内进行，避免扫描整个业务树。

更新包装器或安装器后复用已有密钥出包，使用未占用的文件名：

```sh
linux-mcp-hosts rebuild-deployment --alias server-a \
  --output ~/.local/share/linux-mcp-server/bundles/server-a-deployment-v2.tar.gz
```

已纳管服务器升级 helper 时，在上述 `rebuild-deployment` 增加 `--read-mode privileged`。命令保留账号、独立密钥、主机公钥和原 allowed_roots，包包含 helper、策略、安装器与摘要清单，旧 verified 标记会失效。展示生效根目录后交管理员安装，再真实 verify；不先删除账号重新纳管。不要只复制旧包装器，或仅重新生成不含 helper 的旧版本包。

安装器只接受无 sudo 权限或本工具唯一的精确 helper 授权；拒绝宽泛 sudo。专用 sudoers 为 `codex-ro ALL=(root) NOPASSWD: /usr/local/libexec/linux-mcp-privileged-read ""`，由 `visudo` 检查。helper/策略/上级目录必须由 root 控制；helper 0700、sudoers 0440；不给通用 bash/sh/python/cat 授权。sudoers.d 未启用或目标运行时预检失败时停止，由管理员处理，不关闭保护。

系统、公钥或能力变化时，重新探测，先不接受变化以展示差异：

```sh
linux-mcp-hosts refresh --alias server-a \
  --discovery-json /path/to/new-discovery-result.json \
  --bundle /path/to/new-discovery.tar.gz
```

确认后才添加 `--accept-changes`。接受后重新 prepare、管理员安装与 verify。已有包使用新目录/文件名，不手工覆盖或删除。

## 卸载与本机退役

先展示目标别名、IP、账号 `codex-ro`、home、活动包装器 `/usr/local/libexec/linux-mcp-readonly.py`、策略 `/etc/linux-mcp-readonly/policy.json` 和标记 `/etc/linux-mcp-readonly/managed-account`；说明历史备份保留。仅在用户明确确认后出包：

```sh
python3 <skill-dir>/scripts/prepare_uninstall.py \
  --repository <repo> --output /path/to/server-a-uninstall.tar.gz
```

提供两种路径和 SHA256；管理员默认上传至 `/data/server-a-uninstall.tar.gz`：

```sh
set -eu
BUNDLE='/data/server-a-uninstall.tar.gz'
EXPECTED_SHA256='<本次卸载包SHA256>'
WORK_DIR="$(mktemp -d /var/tmp/linux-mcp-uninstall.XXXXXX)"
printf '%s  %s\n' "$EXPECTED_SHA256" "$BUNDLE" | sha256sum -c -
tar -xzf "$BUNDLE" -C "$WORK_DIR"
sudo bash "$WORK_DIR/uninstall-readonly-account.sh" --confirm-account codex-ro
```

脚本拒绝账号不匹配、UID 0、不安全标记和运行中的账号；中断后重跑仍由标记约束恢复清理。卸载不自动重新纳管，也不自动清理本机密钥。

只有用户明确要求本机彻底退役时，才逐项列出该主机的注册表目录、专用密钥/known_hosts、包、旧 SSH 块和专用日志；确认无共享后，经授权移入回收站或 WSL Trash。旧 SSH 块由原安装的受管脚本清理，不手工改写；缺少脚本或回收站时说明缺口，不永久删除。

保留其他主机画像、共享日志、工具和 MCP 配置。仅在全部主机退役且获明确授权后，才移除共享 MCP 主段和环境段。最后重新列出注册表、检查已列路径并提示新开 Codex 会话；回收站内材料仍可恢复。
