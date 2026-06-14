use config_guard::process::{parse_cmdline, parse_start_time_ticks};

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
fn parses_start_time_from_proc_stat_with_spaces_in_comm() {
    let stat =
        "1234 (name with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123456789 21";

    let start_time = parse_start_time_ticks(stat).expect("start time should parse");

    assert_eq!(start_time, 123456789);
}

#[test]
fn rejects_proc_stat_without_closing_command_name() {
    let stat = "1234 (broken S 1 2 3";

    let error = parse_start_time_ticks(stat).expect_err("invalid stat should fail");

    assert!(error.to_string().contains("closing"));
}
