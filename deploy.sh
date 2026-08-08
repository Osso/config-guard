#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
expected_home="/home/osso"
config_target="${expected_home}/.config/config-guard/config.toml"
service_target="/etc/systemd/system/config-guard.service"
enforcement_marker="/run/config-guard/enforcing"
mode="audit"

usage() {
    echo "usage: $0 [--mode audit|guard]" >&2
}

validate_mode() {
    case "$1" in
        audit | guard) ;;
        *)
            echo "mode must be audit or guard: $1" >&2
            exit 1
            ;;
    esac
}

service_source_for_mode() {
    case "$1" in
        audit) echo "${project_dir}/config/config-guard.service" ;;
        guard) echo "${project_dir}/config/config-guard-guard.service" ;;
    esac
}

restore_service_after_failed_install() {
    local status="$?"
    systemctl start config-guard.service >/dev/null 2>&1 || true
    exit "${status}"
}

install_system_service() {
    local selected_mode="$1"
    local service_source
    service_source="$(service_source_for_mode "${selected_mode}")"

    if [[ "${EUID}" -ne 0 ]]; then
        echo "--install-system requires root" >&2
        exit 1
    fi

    trap restore_service_after_failed_install ERR
    systemctl stop config-guard.service 2>/dev/null || true
    install -Dm600 -o osso -g osso "${project_dir}/config/osso.toml" "${config_target}"
    install -Dm644 "${service_source}" "${service_target}"
    systemctl daemon-reload
    systemctl enable config-guard.service
    systemctl restart config-guard.service
    trap - ERR
}

if [[ "${1:-}" == "--install-system" ]]; then
    if [[ "$#" -ne 2 ]]; then
        usage
        exit 1
    fi
    mode="$2"
    validate_mode "${mode}"
    install_system_service "${mode}"
    exit 0
fi

if [[ "$#" -ne 0 ]]; then
    if [[ "$#" -ne 2 || "$1" != "--mode" ]]; then
        usage
        exit 1
    fi
    mode="$2"
fi
validate_mode "${mode}"

if [[ "${HOME}" != "${expected_home}" ]]; then
    echo "config-guard deployment requires HOME=${expected_home}; got ${HOME}" >&2
    exit 1
fi

verify_service() {
    local selected_mode="$1"
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

    if [[ "${exec_start}" != *"/config-guard ${selected_mode} "* ]]; then
        echo "config-guard service is not running ${selected_mode} mode: ${exec_start}" >&2
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

    if [[ "${selected_mode}" == "guard" ]]; then
        test -f "${enforcement_marker}" || {
            echo "config-guard enforcement marker is missing: ${enforcement_marker}" >&2
            exit 1
        }
    elif [[ -e "${enforcement_marker}" ]]; then
        echo "config-guard audit mode left an enforcement marker: ${enforcement_marker}" >&2
        exit 1
    fi
}

cd "${project_dir}"

cargo install --force --path . --root "${HOME}/.cargo"

authsudo "${project_dir}/deploy.sh" --install-system "${mode}"

verify_service "${mode}"

echo "Installed config-guard -> ${HOME}/.cargo/bin/config-guard"
echo "Installed config -> ${config_target}"
echo "Installed service -> ${service_target}"
echo "Config Guard ${mode} service enabled and active"
