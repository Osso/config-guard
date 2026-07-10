#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
expected_home="/home/osso"
config_target="${expected_home}/.config/config-guard/config.toml"
service_target="/etc/systemd/system/config-guard.service"

install_system_service() {
    local service_source="${project_dir}/config/config-guard.service"

    if [[ "${EUID}" -ne 0 ]]; then
        echo "--install-system requires root" >&2
        exit 1
    fi

    install -Dm644 "${service_source}" "${service_target}"
    systemctl daemon-reload
    systemctl enable config-guard.service
    systemctl restart config-guard.service
}

if [[ "${1:-}" == "--install-system" ]]; then
    if [[ "$#" -ne 1 ]]; then
        echo "usage: $0 --install-system" >&2
        exit 1
    fi
    install_system_service
    exit 0
fi

if [[ "${HOME}" != "${expected_home}" ]]; then
    echo "config-guard deployment requires HOME=${expected_home}; got ${HOME}" >&2
    exit 1
fi

verify_audit_service() {
    local exec_start
    local main_pid
    local restart_count
    local service_type

    systemctl is-enabled --quiet config-guard.service
    sleep 6
    systemctl is-active --quiet config-guard.service

    exec_start="$(systemctl show config-guard.service --property=ExecStart --value)"
    main_pid="$(systemctl show config-guard.service --property=MainPID --value)"
    restart_count="$(systemctl show config-guard.service --property=NRestarts --value)"
    service_type="$(systemctl show config-guard.service --property=Type --value)"

    if [[ "${service_type}" != "notify" ]]; then
        echo "config-guard service does not use readiness notification: ${service_type}" >&2
        exit 1
    fi

    if [[ "${exec_start}" != *"/config-guard audit "* ]]; then
        echo "config-guard service is not running audit mode: ${exec_start}" >&2
        exit 1
    fi

    if [[ "${main_pid}" == "0" ]]; then
        echo "config-guard service has no running process" >&2
        exit 1
    fi

    if [[ "${restart_count}" != "0" ]]; then
        echo "config-guard service restarted during deployment: ${restart_count}" >&2
        exit 1
    fi
}

cd "${project_dir}"

cargo install --force --path . --root "${HOME}/.cargo"

install -Dm600 "config/osso.toml" "${config_target}"
authsudo "${project_dir}/deploy.sh" --install-system

verify_audit_service

echo "Installed config-guard -> ${HOME}/.cargo/bin/config-guard"
echo "Installed config -> ${config_target}"
echo "Installed service -> ${service_target}"
echo "Audit service enabled and active"
