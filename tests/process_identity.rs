use config_guard::process::{
    ProcessIdentity, parse_cmdline, parse_comm, parse_parent_pid, parse_start_time_ticks,
};
use std::path::PathBuf;

#[test]
fn parses_cmdline_nul_separated_arguments() {
    let command = parse_cmdline(b"codex\0--model\0gpt-5\0");

    assert_eq!(command, vec!["codex", "--model", "gpt-5"]);
}

#[test]
fn parses_empty_cmdline_as_empty_vector() {
    let command = parse_cmdline(b"");

    assert!(command.is_empty());
}

#[test]
fn parses_proc_comm_without_trailing_newline() {
    let command = parse_comm("rtk\n");

    assert_eq!(command.as_deref(), Some("rtk"));
}

#[test]
fn ignores_empty_proc_comm() {
    let command = parse_comm("\n");

    assert_eq!(command, None);
}

#[test]
fn parses_start_time_from_proc_stat_with_spaces_in_comm() {
    let stat =
        "1234 (name with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123456789 21";

    let start_time = parse_start_time_ticks(stat).expect("start time should parse");

    assert_eq!(start_time, 123456789);
}

#[test]
fn parses_parent_pid_from_proc_stat_with_spaces_in_comm() {
    let stat =
        "1234 (name with spaces) S 4321 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123456789 21";

    let parent_pid = parse_parent_pid(stat).expect("parent pid should parse");

    assert_eq!(parent_pid, 4321);
}

#[test]
fn rejects_proc_stat_without_closing_command_name() {
    let stat = "1234 (broken S 1 2 3";

    let error = parse_start_time_ticks(stat).expect_err("invalid stat should fail");

    assert!(error.to_string().contains("closing"));
}

#[test]
fn uses_argv0_as_subject_when_exe_link_is_missing() {
    let process = ProcessIdentity {
        pid: 1234,
        executable: None,
        command: vec!["rtk".to_string(), "query".to_string()],
        cwd: None,
        start_time_ticks: Some(42),
        ancestors: Vec::new(),
    };

    let subject = process.subject();

    assert_eq!(subject.executable, PathBuf::from("rtk"));
}
