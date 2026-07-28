#!/usr/bin/env bash
set -euo pipefail

readonly LOG_GROUP="linux-mcp-logread"

if [[ "$#" -eq 0 ]]; then
  set -- \
    "/var/log/messages" \
    "/var/log/secure" \
    "/var/log/mysqld.log"
fi

for log_path in "$@"; do
  case "${log_path}" in
    "/var/log/messages"|"/var/log/secure"|"/var/log/mysqld.log")
      ;;
    *)
      echo "错误：日志路径不在允许列表：${log_path}" >&2
      exit 2
      ;;
  esac
  if [[ ! -e "${log_path}" ]]; then
    continue
  fi
  if [[ -L "${log_path}" || ! -f "${log_path}" ]]; then
    echo "错误：日志不是普通文件：${log_path}" >&2
    exit 1
  fi
  chgrp "${LOG_GROUP}" "${log_path}"
  chmod 0640 "${log_path}"
done
