#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
config_target="${XDG_CONFIG_HOME:-${HOME}/.config}/config-guard/config.toml"
service_target="/etc/systemd/system/config-guard.service"

cd "${project_dir}"

cargo install --force --path .

install -Dm600 "config/osso.toml" "${config_target}"
authsudo install -Dm644 "config/config-guard.service" "${service_target}"
authsudo systemctl daemon-reload

echo "Installed config-guard -> ${HOME}/.cargo/bin/config-guard"
echo "Installed config -> ${config_target}"
echo "Installed service -> ${service_target}"
