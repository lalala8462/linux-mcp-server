#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "错误：必须以 root 执行。" >&2
  exit 1
fi

if [[ "$#" -gt 1 ]]; then
  echo "用法：configure-log-access.sh [账号名]" >&2
  exit 1
fi

readonly TARGET_USER="${1:-codex-ro}"
readonly LOG_GROUP="linux-mcp-logread"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly FIX_SOURCE="${SCRIPT_DIR}/fix-log-permissions.sh"
readonly FIX_TARGET="/usr/local/sbin/linux-mcp-fix-log-permissions"
readonly CONFIGURE_SOURCE="${SCRIPT_DIR}/configure-logrotate.py"
readonly MYSQL_DROPIN_SOURCE="${SCRIPT_DIR}/linux-mcp-logread-mysqld.conf"
readonly MYSQL_DROPIN_DIR="/etc/systemd/system/mysqld.service.d"
readonly MYSQL_DROPIN_TARGET="${MYSQL_DROPIN_DIR}/linux-mcp-logread.conf"
readonly MYSQL_LOG_PATH="/var/log/mysqld.log"
readonly ROTATED_LOG_PATHS=(
  "/var/log/messages"
  "/var/log/secure"
)

if ! id "${TARGET_USER}" >/dev/null 2>&1; then
  echo "错误：账号不存在：${TARGET_USER}" >&2
  exit 1
fi
for required_file in "${FIX_SOURCE}" "${CONFIGURE_SOURCE}" "${MYSQL_DROPIN_SOURCE}"; do
  if [[ ! -f "${required_file}" ]]; then
    echo "错误：文件不存在：${required_file}" >&2
    exit 1
  fi
done
if ! getent group systemd-journal >/dev/null; then
  echo "错误：服务器不存在 systemd-journal 组。" >&2
  exit 1
fi

if ! getent group "${LOG_GROUP}" >/dev/null; then
  groupadd --system "${LOG_GROUP}"
fi
usermod -a -G "${LOG_GROUP}",systemd-journal "${TARGET_USER}"
install -o root -g root -m 0755 "${FIX_SOURCE}" "${FIX_TARGET}"

path_owner_args=()
for log_path in "${ROTATED_LOG_PATHS[@]}"; do
  if [[ ! -e "${log_path}" ]]; then
    echo "跳过不存在的日志：${log_path}"
    continue
  fi
  if [[ -L "${log_path}" || ! -f "${log_path}" ]]; then
    echo "错误：日志不是普通文件：${log_path}" >&2
    exit 1
  fi
  path_owner_args+=("${log_path}" "$(stat -c '%U' "${log_path}")")
done

mysql_permission_mode="not-present"
if [[ -e "${MYSQL_LOG_PATH}" ]]; then
  if [[ -L "${MYSQL_LOG_PATH}" || ! -f "${MYSQL_LOG_PATH}" ]]; then
    echo "错误：日志不是普通文件：${MYSQL_LOG_PATH}" >&2
    exit 1
  fi
  mysql_main_match_count="$(
    /usr/bin/python "${CONFIGURE_SOURCE}" \
      --match-count \
      /etc/logrotate.conf \
      "${MYSQL_LOG_PATH}"
  )"
  mysql_dropin_match_count="$(
    /usr/bin/python "${CONFIGURE_SOURCE}" \
      --match-count \
      /etc/logrotate.d \
      "${MYSQL_LOG_PATH}"
  )"
  mysql_match_count="$((mysql_main_match_count + mysql_dropin_match_count))"
  if [[ "${mysql_main_match_count}" -gt 0 ]]; then
    echo "错误：${MYSQL_LOG_PATH} 直接配置在 /etc/logrotate.conf，脚本不会自动修改主配置。" >&2
    exit 1
  fi
  case "${mysql_match_count}" in
    0)
      if ! systemctl cat mysqld.service >/dev/null 2>&1; then
        echo "错误：${MYSQL_LOG_PATH} 没有轮转配置，且 mysqld.service 不存在。" >&2
        exit 1
      fi
      mysql_unit_properties="$(
        systemctl show mysqld.service \
          -p User \
          -p Group \
          -p PermissionsStartOnly
      )"
      mysql_unit_user="$(sed -n 's/^User=//p' <<<"${mysql_unit_properties}")"
      mysql_permissions_start_only="$(
        sed -n 's/^PermissionsStartOnly=//p' <<<"${mysql_unit_properties}"
      )"
      if [[ -n "${mysql_unit_user}" &&
            "${mysql_unit_user}" != "root" &&
            "${mysql_permissions_start_only}" != "true" &&
            "${mysql_permissions_start_only}" != "yes" ]]; then
        echo "错误：mysqld.service 以 ${mysql_unit_user} 运行，且 PermissionsStartOnly 未启用；" >&2
        echo "拒绝安装需要 root 权限的 ExecStartPost。" >&2
        exit 1
      fi
      mysql_permission_mode="systemd-dropin"
      ;;
    1)
      path_owner_args+=("${MYSQL_LOG_PATH}" "$(stat -c '%U' "${MYSQL_LOG_PATH}")")
      mysql_permission_mode="logrotate"
      ;;
    *)
      echo "错误：${MYSQL_LOG_PATH} 匹配了多个 logrotate 配置：${mysql_match_count}" >&2
      exit 1
      ;;
  esac
fi

if [[ "${#path_owner_args[@]}" -gt 0 ]]; then
  /usr/bin/python "${CONFIGURE_SOURCE}" \
    /etc/logrotate.d \
    "${LOG_GROUP}" \
    "${FIX_TARGET}" \
    "${path_owner_args[@]}"
fi

if [[ "${mysql_permission_mode}" == "systemd-dropin" ]]; then
  install -d -o root -g root -m 0755 "${MYSQL_DROPIN_DIR}"
  install -o root -g root -m 0644 "${MYSQL_DROPIN_SOURCE}" "${MYSQL_DROPIN_TARGET}"
  systemctl daemon-reload
fi
"${FIX_TARGET}"

echo "日志只读权限配置完成："
echo "  account=${TARGET_USER}"
echo "  journal_group=systemd-journal"
echo "  log_group=${LOG_GROUP}"
echo "  permission_hook=${FIX_TARGET}"
echo "  mysql_permission_mode=${mysql_permission_mode}"
