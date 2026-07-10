#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
expected_home="/home/osso"
config_target="${expected_home}/.config/config-guard/config.toml"
service_target="/etc/systemd/system/config-guard.service"

if [[ "${HOME}" != "${expected_home}" ]]; then
    echo "config-guard deployment requires HOME=${expected_home}; got ${HOME}" >&2
    exit 1
fi

verify_audit_service() {
    local exec_start
    local main_pid

    systemctl is-enabled --quiet config-guard.service
    sleep 3
    systemctl is-active --quiet config-guard.service

    exec_start="$(systemctl show config-guard.service --property=ExecStart --value)"
    main_pid="$(systemctl show config-guard.service --property=MainPID --value)"

    if [[ "${exec_start}" != *"/config-guard audit "* ]]; then
        echo "config-guard service is not running audit mode: ${exec_start}" >&2
        exit 1
    fi

    if [[ "${main_pid}" == "0" ]]; then
        echo "config-guard service has no running process" >&2
        exit 1
    fi
}

cd "${project_dir}"

cargo install --force --path . --root "${HOME}/.cargo"

install -Dm600 "config/osso.toml" "${config_target}"
authsudo install -Dm644 "config/config-guard.service" "${service_target}"
authsudo systemctl daemon-reload
authsudo systemctl enable config-guard.service
authsudo systemctl restart config-guard.service

verify_audit_service

echo "Installed config-guard -> ${HOME}/.cargo/bin/config-guard"
echo "Installed config -> ${config_target}"
echo "Installed service -> ${service_target}"
echo "Audit service enabled and active"
