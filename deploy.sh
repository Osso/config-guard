#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
binary_target="${HOME}/.local/bin/config-guard"
config_target="${XDG_CONFIG_HOME:-${HOME}/.config}/config-guard/config.toml"
service_target="/etc/systemd/system/config-guard.service"

cd "${project_dir}"

cargo build --release

install -Dm755 "target/release/config-guard" "${binary_target}"
install -Dm600 "config/osso.toml" "${config_target}"
authsudo install -Dm644 "config/config-guard.service" "${service_target}"
authsudo systemctl daemon-reload

echo "Installed config-guard -> ${binary_target}"
echo "Installed config -> ${config_target}"
echo "Installed service -> ${service_target}"
