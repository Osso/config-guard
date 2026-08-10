use super::{CountingPrompt, resolve_owned_ancestor_prompt};
use crate::policy::{AccessKind, Decision};
use crate::process::{ProcessAncestor, ProcessIdentity};
use std::path::PathBuf;

#[test]
fn resolve_reuses_allow_across_detached_runners_in_one_pi_session() {
    let first_process = python_process_with_pi_ancestors(42, 100, &[(8, 60), (7, 50)]);
    let next_process = python_process_with_pi_ancestors(43, 200, &[(9, 70), (7, 50)]);
    let prompt = CountingPrompt::new(Decision::Allow);
    let mut cache = super::PromptDecisionCache::default();

    resolve_owned_ancestor_prompt(
        &prompt,
        &mut cache,
        &first_process,
        AccessKind::Read,
        "/home/osso/.local/state/pi/control.sqlite",
        "/home/osso/.local/state/pi",
    );
    resolve_owned_ancestor_prompt(
        &prompt,
        &mut cache,
        &next_process,
        AccessKind::Write,
        "/home/osso/.local/state/pi/control.sqlite-wal",
        "/home/osso/.local/state/pi",
    );

    assert_eq!(prompt.calls.get(), 1);
}

#[test]
fn resolve_reuses_allow_across_different_pi_sessions() {
    let first_process = python_process_with_nested_pi_session(42, 100, (8, 60), (7, 50), (5, 30));
    let next_process = python_process_with_nested_pi_session(43, 200, (11, 80), (10, 70), (5, 30));
    let prompt = CountingPrompt::new(Decision::Allow);
    let mut cache = super::PromptDecisionCache::default();

    resolve_owned_ancestor_prompt(
        &prompt,
        &mut cache,
        &first_process,
        AccessKind::Read,
        "/home/osso/.local/state/pi/control.sqlite",
        "/home/osso/.local/state/pi",
    );
    resolve_owned_ancestor_prompt(
        &prompt,
        &mut cache,
        &next_process,
        AccessKind::Read,
        "/home/osso/.local/state/pi/control.sqlite",
        "/home/osso/.local/state/pi",
    );

    assert_eq!(prompt.calls.get(), 1);
}

#[test]
fn resolve_denies_same_basename_owner_from_different_executable_path() {
    let first_process =
        python_process_with_owner_path(42, 100, "/home/osso/.local/share/pi/pi", 7, 50);
    let next_process = python_process_with_owner_path(43, 200, "/opt/pi/pi", 8, 60);
    let mut prompt = CountingPrompt::new(Decision::Allow);
    let mut cache = super::PromptDecisionCache::default();

    let first = resolve_owned_ancestor_prompt(
        &prompt,
        &mut cache,
        &first_process,
        AccessKind::Read,
        "/home/osso/.local/state/pi/control.sqlite",
        "/home/osso/.local/state/pi",
    );
    prompt.set_decision(Decision::Deny);
    let second = resolve_owned_ancestor_prompt(
        &prompt,
        &mut cache,
        &next_process,
        AccessKind::Read,
        "/home/osso/.local/state/pi/control.sqlite",
        "/home/osso/.local/state/pi",
    );

    assert_eq!(first, Decision::Allow);
    assert_eq!(second, Decision::Deny);
    assert_eq!(prompt.calls.get(), 2);
}

#[test]
fn resolve_does_not_share_allow_with_different_helper_path() {
    let first_process = python_process_with_pi_ancestors(42, 100, &[(7, 50)]);
    let mut next_process = python_process_with_pi_ancestors(43, 200, &[(7, 50)]);
    next_process.executable = Some(PathBuf::from("/usr/bin/python3.12"));
    next_process.command = vec!["python3.12".to_string()];
    let prompt = CountingPrompt::new(Decision::Allow);
    let mut cache = super::PromptDecisionCache::default();

    resolve_owned_ancestor_prompt(
        &prompt,
        &mut cache,
        &first_process,
        AccessKind::Read,
        "/home/osso/.local/state/pi/control.sqlite",
        "/home/osso/.local/state/pi",
    );
    resolve_owned_ancestor_prompt(
        &prompt,
        &mut cache,
        &next_process,
        AccessKind::Read,
        "/home/osso/.local/state/pi/control.sqlite",
        "/home/osso/.local/state/pi",
    );

    assert_eq!(prompt.calls.get(), 2);
}

#[test]
fn resolve_does_not_share_allow_past_owner_without_generation_identity() {
    let pi_executable = PathBuf::from("/home/osso/.local/share/pi/pi");
    let first_process = cat_process_with_ancestors(
        42,
        100,
        vec![
            ProcessAncestor {
                pid: 8,
                executable: pi_executable.clone(),
                start_time_ticks: Some(60),
            },
            ProcessAncestor {
                pid: 7,
                executable: pi_executable.clone(),
                start_time_ticks: None,
            },
            ProcessAncestor {
                pid: 5,
                executable: pi_executable.clone(),
                start_time_ticks: Some(30),
            },
        ],
    );
    let next_process = cat_process_with_ancestors(
        43,
        200,
        vec![
            ProcessAncestor {
                pid: 9,
                executable: pi_executable.clone(),
                start_time_ticks: Some(70),
            },
            ProcessAncestor {
                pid: 7,
                executable: pi_executable.clone(),
                start_time_ticks: None,
            },
            ProcessAncestor {
                pid: 5,
                executable: pi_executable,
                start_time_ticks: Some(30),
            },
        ],
    );
    let prompt = CountingPrompt::new(Decision::Allow);
    let mut cache = super::PromptDecisionCache::default();

    resolve_owned_ancestor_prompt(
        &prompt,
        &mut cache,
        &first_process,
        AccessKind::Read,
        "/home/osso/.local/state/pi/control.sqlite",
        "/home/osso/.local/state/pi",
    );
    resolve_owned_ancestor_prompt(
        &prompt,
        &mut cache,
        &next_process,
        AccessKind::Read,
        "/home/osso/.local/state/pi/control.sqlite",
        "/home/osso/.local/state/pi",
    );

    assert_eq!(prompt.calls.get(), 2);
}

fn python_process_with_pi_ancestors(
    pid: i32,
    start_time_ticks: u64,
    pi_generations: &[(i32, u64)],
) -> ProcessIdentity {
    let pi_executable = PathBuf::from("/home/osso/.local/share/pi/pi");
    let ancestors = pi_generations
        .iter()
        .map(|(pid, start_time_ticks)| ProcessAncestor {
            pid: *pid,
            executable: pi_executable.clone(),
            start_time_ticks: Some(*start_time_ticks),
        })
        .collect();

    let mut process = cat_process_with_ancestors(pid, start_time_ticks, ancestors);
    process.executable = Some(PathBuf::from(
        "/home/osso/.local/share/uv/python/cpython-3.12.12-linux-x86_64-gnu/bin/python3.12",
    ));
    process.command = vec!["python3.12".to_string()];
    process
}

fn python_process_with_owner_path(
    pid: i32,
    start_time_ticks: u64,
    owner_path: &str,
    owner_pid: i32,
    owner_start_time_ticks: u64,
) -> ProcessIdentity {
    let mut process = python_process_with_pi_ancestors(
        pid,
        start_time_ticks,
        &[(owner_pid, owner_start_time_ticks)],
    );
    let owner_executable = PathBuf::from(owner_path);
    process.ancestors[0] = owner_executable.clone();
    process.ancestor_processes[0].executable = owner_executable;
    process
}

fn python_process_with_nested_pi_session(
    pid: i32,
    start_time_ticks: u64,
    runner: (i32, u64),
    session: (i32, u64),
    distant_controller: (i32, u64),
) -> ProcessIdentity {
    let mut process = cat_process_with_nested_pi_session(
        pid,
        start_time_ticks,
        runner,
        session,
        distant_controller,
    );
    process.executable = Some(PathBuf::from(
        "/home/osso/.local/share/uv/python/cpython-3.12.12-linux-x86_64-gnu/bin/python3.12",
    ));
    process.command = vec!["python3.12".to_string()];
    process
}

fn cat_process_with_nested_pi_session(
    pid: i32,
    start_time_ticks: u64,
    runner: (i32, u64),
    session: (i32, u64),
    distant_controller: (i32, u64),
) -> ProcessIdentity {
    let pi_executable = PathBuf::from("/home/osso/.local/share/pi/pi");
    let ancestors = vec![
        ProcessAncestor {
            pid: runner.0,
            executable: pi_executable.clone(),
            start_time_ticks: Some(runner.1),
        },
        ProcessAncestor {
            pid: session.0,
            executable: pi_executable.clone(),
            start_time_ticks: Some(session.1),
        },
        ProcessAncestor {
            pid: 99,
            executable: PathBuf::from("/usr/bin/authsudo"),
            start_time_ticks: Some(90),
        },
        ProcessAncestor {
            pid: distant_controller.0,
            executable: pi_executable,
            start_time_ticks: Some(distant_controller.1),
        },
    ];

    cat_process_with_ancestors(pid, start_time_ticks, ancestors)
}

fn cat_process_with_ancestors(
    pid: i32,
    start_time_ticks: u64,
    ancestor_processes: Vec<ProcessAncestor>,
) -> ProcessIdentity {
    ProcessIdentity {
        pid,
        executable: Some(PathBuf::from("/usr/bin/cat")),
        command: vec!["cat".to_string()],
        cwd: None,
        start_time_ticks: Some(start_time_ticks),
        ancestors: ancestor_processes
            .iter()
            .map(|ancestor| ancestor.executable.clone())
            .collect(),
        ancestor_processes,
    }
}
