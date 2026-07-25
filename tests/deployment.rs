use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn project_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

#[test]
fn systemd_unit_runs_audit_mode_at_boot() {
    let unit =
        fs::read_to_string(project_file("config/config-guard.service")).expect("read systemd unit");

    assert!(unit.contains("Type=notify"));
    assert!(unit.contains("NotifyAccess=main"));
    assert!(unit.contains("ExecStart=/home/osso/.cargo/bin/config-guard audit "));
    assert!(unit.contains("--path /home/osso/.ssh"));
    assert!(unit.contains("WantedBy=multi-user.target"));
}

#[test]
fn systemd_guard_unit_runs_guard_mode() {
    let unit = fs::read_to_string(project_file("config/config-guard-guard.service"))
        .expect("read guard systemd unit");

    assert!(unit.contains("Type=notify"));
    assert!(unit.contains("NotifyAccess=main"));
    assert!(unit.contains("ExecStart=/home/osso/.cargo/bin/config-guard guard "));
    assert!(unit.contains("--path /home/osso/.ssh"));
    assert!(unit.contains("WantedBy=multi-user.target"));
}

#[test]
fn deploy_rejects_unknown_mode_before_home_validation() {
    let output = Command::new(project_file("deploy.sh"))
        .args(["--mode", "invalid"])
        .env("HOME", "/tmp/config-guard-invalid-home")
        .output()
        .expect("run deploy with invalid mode");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(stderr.contains("mode must be audit or guard"), "{stderr}");
    assert!(!stderr.contains("requires HOME"), "{stderr}");
}

#[test]
fn audit_docs_state_that_later_submounts_require_separate_marks() {
    let docs = fs::read_to_string(project_file("docs/wiki/systems/config-guard.md"))
        .expect("read system documentation");

    assert!(docs.contains("mounts created after startup are not covered"));
    assert!(docs.contains("restart Config Guard after adding a submount"));
}

#[test]
fn deploy_defines_explicit_mode_activation_contract() {
    let deploy = fs::read_to_string(project_file("deploy.sh")).expect("read deploy script");

    assert!(deploy.contains("expected_home=\"/home/osso\""));
    assert!(!deploy.contains("XDG_CONFIG_HOME"));
    assert!(deploy.contains("mode=\"audit\""));
    assert!(deploy.contains("audit | guard"));
    assert!(deploy.contains("config/config-guard.service"));
    assert!(deploy.contains("config/config-guard-guard.service"));
    assert!(deploy.contains("cargo install --force --path . --root \"${HOME}/.cargo\""));
    assert!(deploy.contains("install -Dm600 \"config/osso.toml\""));
    assert_eq!(deploy.matches("authsudo ").count(), 1);
    assert!(deploy.contains("authsudo \"${project_dir}/deploy.sh\" --install-system \"${mode}\""));
    assert!(!deploy.contains("authsudo \"$0\""));
    assert!(deploy.contains("install -Dm644 \"${service_source}\" \"${service_target}\""));
    assert!(deploy.contains("systemctl daemon-reload"));
    assert!(deploy.contains("systemctl enable config-guard.service"));
    assert!(deploy.contains("systemctl restart config-guard.service"));
    assert!(deploy.contains("systemctl is-enabled --quiet config-guard.service"));
    assert!(deploy.contains("sleep 6"));
    assert!(deploy.contains("systemctl is-active --quiet config-guard.service"));
    assert!(deploy.contains("--property=ExecStart --value"));
    assert!(deploy.contains("--property=MainPID --value"));
    assert!(deploy.contains("--property=Type --value"));
    assert!(deploy.contains("--property=NRestarts --value"));
    assert!(deploy.contains("verify_service \"${mode}\""));
}
