use std::fs;
use std::path::PathBuf;

fn project_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

#[test]
fn systemd_unit_runs_audit_mode_at_boot() {
    let unit =
        fs::read_to_string(project_file("config/config-guard.service")).expect("read systemd unit");

    assert!(unit.contains("ExecStart=/home/osso/.cargo/bin/config-guard audit "));
    assert!(unit.contains("WantedBy=multi-user.target"));
}

#[test]
fn deploy_defines_audit_service_activation_contract() {
    let deploy = fs::read_to_string(project_file("deploy.sh")).expect("read deploy script");

    assert!(deploy.contains("expected_home=\"/home/osso\""));
    assert!(!deploy.contains("XDG_CONFIG_HOME"));
    assert!(deploy.contains("cargo install --force --path . --root \"${HOME}/.cargo\""));
    assert!(deploy.contains("install -Dm600 \"config/osso.toml\""));
    assert!(deploy.contains("authsudo install -Dm644 \"config/config-guard.service\""));
    assert!(deploy.contains("authsudo systemctl daemon-reload"));
    assert!(deploy.contains("authsudo systemctl enable config-guard.service"));
    assert!(deploy.contains("authsudo systemctl restart config-guard.service"));
    assert!(deploy.contains("systemctl is-enabled --quiet config-guard.service"));
    assert!(deploy.contains("sleep 3"));
    assert!(deploy.contains("systemctl is-active --quiet config-guard.service"));
    assert!(deploy.contains("--property=ExecStart --value"));
    assert!(deploy.contains("--property=MainPID --value"));
    assert!(deploy.contains("verify_audit_service"));
}
