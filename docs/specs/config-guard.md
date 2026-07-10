# Config Guard

Config Guard is an interactive policy monitor for sensitive configuration file access. Its source lives under `src/`, its local policy lives in `config/osso.toml`, and operational wiring lives in `config/config-guard.service`; implementation details belong in [the system wiki](../wiki/systems/config-guard.md).

## What it must do

Policy decisions:

- [x] Allow same-owner access to owned paths without prompting.
- [x] Require explicit executable or executable-prefix rules for versioned Claude binaries; matching the owner name alone must not implicitly allow them.
- [x] Let explicit owner allow rules take precedence over sensitive-path dev-tool prompts.
- [x] Let ancestor-aware executable-prefix rules allow spawned shell helpers only when the expected ancestor is present.
- [x] Let ancestor-aware subject rules allow helper binaries only when a trusted parent or ancestor is present.
- [x] Choose the most specific owned-path rule when multiple owned paths match.
- [x] Allow configured shared paths for common desktop processes.
- [x] Let shared paths allow all subjects with `*`.
- [x] Enforce shared-path access kinds, including read-only shared paths.
- [x] Let owned paths allow all subjects with `*`.
- [x] Support file-prefix matching for shared paths when `path_prefix = true`.
- [x] Prompt on cross-owner reads with the configured fail-open default.
- [x] Prompt on cross-owner writes with a write-specific reason.
- [x] Prompt when configured dev tools read sensitive paths.
- [x] Treat an explicit prompt deny as applying only to the current event.
- [ ] Keep ad hoc copy operations against protected configuration trees out of durable allow policy unless a stable owner or workflow justifies them.

Audit and guard runtime:

- [x] In audit mode, log policy violations as `FORBID audit` lines for cross-owner access without denying the operation.
- [x] In guard mode, invoke the configured prompt command for cross-owner access.
- [x] Reuse an approved prompt answer for the same executable, access kind, reason, and policy scope.
- [x] Do not cache explicit prompt denials as durable executable approvals.
- [x] Watch multiple roots from one process.
- [x] Canonicalize configured roots and exclusions before monitoring so scope filtering is independent of the service working directory and `..` spelling.
- [x] In audit mode, use mount notifications plus root/exclusion filtering so existing and future descendants are covered without recursive-mark races.
- [x] In audit mode, bind executable fallback identities to pidfd process generations and pair open/close identities by file object identity so PID reuse and renames cannot produce stale attribution.
- [x] In audit mode, preserve every read/write close classification present in each received close-event mask; the kernel may coalesce duplicate notifications, so log counts are not close-event or file-descriptor counts.
- [x] In audit mode, filter events outside configured roots even when they share a monitored mount.
- [x] In guard mode, walk watched directory trees without following symlinked directories.
- [x] In guard mode, skip excluded directories when marking watched trees.
- [x] Treat fanotify queue overflow or an invalid event descriptor as a fatal monitoring error instead of silently losing coverage.
- [x] Evaluate policy with an unknown subject when process inspection fails instead of bypassing the policy.
- [x] Make deployment enable and restart the systemd unit in audit mode, wait for systemd readiness, then check its mode, active process, restart count, and boot enablement.
- [ ] Support a documented manual systemd transition to guard mode and rollback after audit burn-in.

Process identity:

- [x] Parse nul-separated command lines.
- [x] Treat empty command lines as empty vectors.
- [x] Parse `/proc/<pid>/comm` values with and without trailing newlines.
- [x] Ignore empty `/proc/<pid>/comm` values.
- [x] Parse process start time and parent PID from `/proc/<pid>/stat` when the command name contains spaces.
- [x] Reject malformed `/proc/<pid>/stat` values without a closing command name.
- [x] Use argv0 as the subject when the executable symlink cannot be read.
- [x] Construct an explicit unknown subject when process inspection cannot produce an identity.

Learning:

- [x] Learn the owning configuration root for subdirectories under `$HOME/.config`.
- [x] Treat `.ssh` as its own sensitive root.
- [x] Treat `.kube` as its own configuration root.
- [x] Treat `.codex` as its own configuration root.
- [x] Ignore paths outside known configuration roots.
- [x] Map symlinked configuration targets back to their logical configuration root.

Reconcile:

- [x] Keep configured directories.
- [x] Report unconfigured directories with matching binaries as association candidates.
- [x] Match association candidates with uppercase and scoped configuration directory names.
- [x] Report unconfigured directories without matching binaries as archive candidates.
- [x] Never archive the configured archive directory.
- [x] When `--apply` is used, move unconfigured archive candidates into the archive directory.
- [x] When `--apply` is used, append accepted associations to the policy config file.

Local policy file:

- [x] Parse `config/osso.toml`.
- [x] Allow known owners configured in `config/osso.toml`.
- [x] Prompt dev tools that read sensitive configured paths.
- [x] Allow Claude-spawned shell helpers for configured Claude paths when the Claude ancestor rule matches.
- [x] Allow Claude-spawned snapshot helpers covered by the local policy.
- [ ] Keep every durable allow rule tied to an owner, shared resource, or repeatable workflow observed across more than one ad hoc copy command.

CLI and deployment:

- [x] Provide `audit`, `guard`, `reconcile`, and `test-prompt` subcommands.
- [x] Require at least one `--path` for `audit` and `guard`.
- [x] Support `--exclude-path` for watched trees.
- [x] Support a configurable policy path through `--config`, falling back to the default user config path when present.
- [x] Deploy the release binary, local policy config, and systemd service through `deploy.sh`.

## How it works

- [System design](../wiki/systems/config-guard.md)
- [Policy model](../wiki/systems/config-guard-policy.md)
- [Audit learning](../wiki/systems/config-guard-learning.md)
- [Reconcile workflow](../wiki/systems/config-guard-reconcile.md)

## Implementation inventory

- `src/main.rs` - CLI command parsing and command wiring for audit, guard, reconcile, and prompt testing.
- `src/fanotify.rs` - mode-specific fanotify setup, mount/tree marking, scope filtering, overflow handling, prompt resolution, and guard responses.
- `src/fanotify/audit.rs` - audit open-identity capture, close-event classification, policy evaluation, learning, and logging orchestration.
- `src/fanotify/audit_identity.rs` - bounded PID/object-identity queues bridging audit open and close events across path renames.
- `src/fanotify/audit_process.rs` - bounded TTL cache of executable identities keyed by pidfd process generation for processes too short-lived for procfs inspection.
- `src/fanotify/event.rs` - fanotify metadata parsing, pidfd process-generation extraction, event target/object identity, and descriptor cleanup.
- `src/fanotify/watch.rs` - audit mount marks and guard tree-mark installation.
- `src/policy.rs` - policy config types, subject matching, ownership checks, sensitive-path checks, shared-path checks, and prompt decisions.
- `src/process.rs` - `/proc` process inspection, process subject extraction, command parsing, ancestor discovery, and Wayland environment reads.
- `src/prompt.rs` - authd and command prompt adapters plus timeout and exit-status decision mapping.
- `src/systemd_notify.rs` - systemd readiness notification transport and socket addressing.
- `src/learning.rs` - audit observation aggregation and learned TOML output for candidate owned paths.
- `src/reconcile.rs` - config-home inventory, association/archive planning, and apply-mode config/archive updates.
- `src/lib.rs` - public module exports for integration tests.
- `config/osso.toml` - local policy used by the deployed audit service.
- `config/config-guard.service` - systemd unit for the local guard service.
- `deploy.sh` - release build and install path for the binary, policy, and service file.
- `run-tests.sh` - project verification script.

## Tests asserting this spec

- `tests/policy.rs` - policy decision contract.
- `tests/root_integration.rs` - fanotify audit and guard behavior requiring root privileges.
- `tests/process_identity.rs` - process identity parsing contract.
- `tests/learning.rs` - audit learning root selection and alias mapping.
- `tests/reconcile.rs` - reconcile planning and apply behavior.
- `tests/config_file.rs` - local `config/osso.toml` policy expectations.
- `tests/deployment.rs` - static audit-mode unit and deploy activation-script contract.
- `src/fanotify.rs` unit tests - mode masks, merged close classification, overflow handling, scope filtering, unknown-subject evaluation, directory walking, and excluded-tree behavior.
- `src/fanotify/audit_identity.rs` unit tests - queued identities, bounded eviction, PID-generation replacement, take-on-close, and failed-open invalidation.
- `src/fanotify/audit_process.rs` unit tests - exec-identity TTL, capacity eviction, dynamic-loader handling, and pidfd generation isolation.
- `src/systemd_notify.rs` unit tests - readiness message delivery over the systemd notification socket.

## Known gaps (current cycle)

- [ ] Add machine-checkable coverage for the CLI subcommand surface and default config-path behavior.
- [ ] Complete audit burn-in and review observed violations before enabling guard mode.
- [ ] Add a policy review checklist for turning observed audit lines into durable allow rules, including the "no ad hoc cp allow" rule.

## Out of scope

- Kernel fanotify semantics beyond the event types Config Guard consumes.
- Prompt UI design beyond the request/decision contract exposed through `prompt.rs`.
- Full host policy for machines other than the local `osso` profile in `config/osso.toml`.
- Automatically switching from audit mode to guard mode; enforcement remains a deliberate post-burn-in decision.
- Race-free coverage of directories created after guard-mode startup; guard currently uses inode tree marks.
- Pre-write denial based on write-specific policy; `FAN_CLOSE_WRITE` reports writes only after they complete.
