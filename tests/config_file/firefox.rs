use super::{parse_osso_config, subject};
use config_guard::policy::{AccessKind, Decision, Policy};

#[test]
fn osso_config_allows_firefox_local_dconf_read() {
    let policy = Policy::new(parse_osso_config());

    let decision = policy.decide(
        &subject("firefox"),
        "/home/osso/.config/dconf/user",
        AccessKind::Read,
    );

    assert_eq!(decision, Decision::Allow);
}

#[test]
fn osso_config_allows_firefox_local_crashhelper_log_read_and_write() {
    let policy = Policy::new(parse_osso_config());
    let subject = subject("crashhelper");
    let path = "/home/osso/.config/firefox/Crash Reports/crash_helper_server.log";
    let decisions =
        [AccessKind::Read, AccessKind::Write].map(|access| policy.decide(&subject, path, access));

    assert_eq!(decisions, [Decision::Allow, Decision::Allow]);
}
