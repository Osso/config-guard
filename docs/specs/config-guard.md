# Config Guard

Config Guard is an interactive policy monitor for sensitive configuration file access. Its source lives under `src/`, its local policy lives in `config/osso.toml`, and operational wiring lives in `config/config-guard.service`; implementation details belong in [the system wiki](../wiki/systems/config-guard.md).

## What it must do

Policy decisions:

- [x] Allow every access kind when the target path's final component is exactly `.gitignore`, before ownership, non-owner denial, shared-path, sensitive-path, or prompt rules; lookalike names such as `.gitignore.lock` remain governed normally.
- [x] Allow same-owner access to owned paths without prompting.
- [x] Require explicit executable or executable-prefix rules for versioned Claude binaries; matching the owner name alone must not implicitly allow them.
- [x] Let explicit owner allow rules take precedence over sensitive-path dev-tool prompts.
- [x] Let ancestor-aware executable-prefix rules allow spawned shell helpers only when the expected ancestor is present.
- [x] Let ancestor-aware subject rules allow helper binaries only when a trusted parent or ancestor is present.
- [x] Choose the most specific owned-path rule when multiple owned paths match.
- [x] Protect only explicitly listed `owned_paths`; generic descendants of monitored roots remain unowned and allowed when no other policy rule matches.
- [x] Allow configured shared paths for common desktop processes.
- [x] Let shared paths allow all subjects with `*`.
- [x] Enforce shared-path access kinds, including read-only shared paths.
- [x] Let owned paths allow all subjects with `*`.
- [x] Let an owned path opt into unconditional non-owner denial before shared-path and prompt rules.
- [x] Enforce unconditional non-owner denial in guard mode without invoking prompt or fail-open fallback.
- [x] Support file-prefix matching for shared paths when `path_prefix = true`.
- [x] Prompt on cross-owner reads with the configured fail-open default.
- [x] Prompt on cross-owner writes with a write-specific reason.
- [x] Prompt when configured dev tools read sensitive paths.
- [x] Treat an explicit prompt deny as applying only to the current event.
- [ ] Keep ad hoc copy operations against protected configuration trees out of durable allow policy unless a stable owner or workflow justifies them.

Audit and guard runtime:

- [x] In audit mode, log policy violations as `FORBID audit` lines for cross-owner access without denying the operation.
- [x] In audit-prompt mode, invoke the configured session prompt for policy Prompt decisions, log the user's decision as `FORBID audit-prompt`, and always allow the underlying access.
- [x] In guard mode, log policy violations as `FORBID guard` lines while invoking the configured prompt command for cross-owner access.
- [x] In guard mode, continue servicing watched-path permission events while a prompt is active so prompt helpers can read watched files without deadlocking the original access.
- [x] Wait up to 35 seconds for authd's bounded authorization-service response before applying the configured default decision.
- [x] Forward the target process's `XDG_SESSION_ID` so authd can verify and recover the exact locked session.
- [x] Keep `FORBID audit` specific to audit mode; guard violations use `FORBID guard`.
- [x] In guard mode, block an open when the prompt explicitly denies it.
- [x] Reuse one Allow or Deny prompt answer for the same verified process generation, access kind, and reason across policy scopes.
- [x] Before presenting each queued guard prompt, revalidate the verified process generation; if the process exited or the PID was reused, discard the stale prompt and apply the configured default to its pending events.
- [x] On an explicit Allow for a cross-owner helper under its owning process, create a runtime-only ancestry authorization keyed by the exact helper executable, the root generation of the nearest contiguous chain of matching owner executables, and owned scope; cover all access kinds in that scope until Config Guard restarts.
- [x] Reuse runtime ancestry authorization for short-lived detached runners in the same contiguous owner chain; a different owner-session root requires a new prompt, and a matching owner executable separated by a non-owner process does not share authorization.
- [x] Require a new prompt when no matching runtime ancestry authorization exists, and do not create ancestry authorization from an explicit Deny or a default decision.
- [x] Do not cache prompt answers or create ancestry authorization when executable or process-generation identity is unavailable.
- [x] Watch multiple roots from one process.
- [x] Keep fanotify monitoring scope independent from policy ownership scope: broad monitored roots provide observation coverage but do not implicitly protect every descendant.
- [x] Canonicalize configured roots and exclusions before monitoring so scope filtering is independent of the service working directory and `..` spelling.
- [x] Expand configured roots with resolved direct symlink targets under `$HOME/.config` so logical configuration trees remain monitored across mount boundaries.
- [x] Include `$HOME/.ssh` and `$HOME/.kube` in both deployed audit and guard monitoring scopes.
- [x] Keep `$HOME/.kube` owned by `kubectl` with `flux` as an explicit allowed subject; monitoring scope does not grant ownership.
- [x] In audit mode, use mount notifications plus root/exclusion filtering so existing and future descendants on each marked mount are covered without recursive-mark races.
- [x] Document that submounts created after startup require a Config Guard restart because `FAN_MARK_MOUNT` does not follow later mounts.
- [x] Reject unsupported fanotify metadata versions instead of parsing an unknown ABI.
- [x] In audit mode, bind executable fallback identities to pidfs-backed pidfd process generations and fail explicitly when the kernel cannot provide that invariant; pair open/close identities by file object identity so PID reuse and renames cannot produce stale attribution.
- [x] In audit mode, preserve every read/write close classification present in each received close-event mask; the kernel may coalesce duplicate notifications, so log counts are not close-event or file-descriptor counts.
- [x] In audit mode, filter events outside configured roots even when they share a monitored mount.
- [x] In guard mode, walk watched directory trees without following symlinked directories.
- [x] In guard mode, skip excluded directories when marking watched trees.
- [x] Treat fanotify queue overflow or an invalid event descriptor as a fatal monitoring error instead of silently losing coverage.
- [x] Evaluate policy with an unknown subject when process inspection fails instead of bypassing the policy.
- [x] Make deployment explicitly select audit or guard mode, wait for systemd readiness, then check the selected mode, active process, restart count, and boot enablement.
- [x] Make guard service startup want `secrets-broker.service`.
- [x] Create `/run/config-guard/enforcing` only after guard readiness; audit mode must not create the marker.
- [x] Verify the selected service mode and marker presence or absence during deployment.
- [x] Default deployment to audit mode and provide explicit guard transition and audit rollback commands while documenting future-directory, fail-open, and post-write limitations.
- [x] Keep audit-prompt separate from the deployed audit service so dialog testing cannot enforce access.

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
- [x] Protect `$HOME/.local/share/firefox-backup` for owner `firefox-profile-backup`, allow `sqlite3` only with a `firefox-profile-backup` ancestor, and allow `systemd-executor` only with a `systemd` ancestor; matching subjects without the required ancestor remain prompted.
- [x] Allow `syncthing-cli` as a subject for both `$HOME/.config/syncthing-cli` and `$HOME/.config/syncthing`.
- [x] Temporarily allow subject `git` to read only `$HOME/.config/gc` and `$HOME/.config/gmail-cli` because their credential files are intentionally tracked in the Provisioning repository; do not allow Git helpers or broader sensitive-config access, and retire this exception when tracked credential storage is replaced by a workflow that does not require Git to open these files.
- [x] Protect `/var/lib/secrets-broker` as an owned credential store for `secrets-broker`, allow only `secrets-broker-admin` as an additional subject, and deny every other subject before prompt or fail-open handling; this strict denial remains separate from guard-mode prompt fallback.
- [x] Leave `/etc/NetworkManager/dispatcher.d` and descendants unprotected for all subjects and access kinds through an explicit shared-path exception; keep `/etc/NetworkManager` and sibling subtrees owned and protected.
- [x] Keep broad ownership entries removed for `/etc`, `/var`, `/var/log`, `$HOME/.local/share`, and `$HOME/.local/state`; protect sensitive subdirectories by listing them explicitly.
- [x] Prompt dev tools that read sensitive configured paths.
- [x] Allow Claude-spawned shell helpers for configured Claude paths when the Claude ancestor rule matches.
- [x] Allow Claude-spawned snapshot helpers covered by the local policy.
- [ ] Keep every durable allow rule tied to an owner, shared resource, or repeatable workflow observed across more than one ad hoc copy command.

CLI and deployment:

- [x] Provide `audit`, `audit-prompt`, `guard`, `reconcile`, and `test-prompt` subcommands.
- [x] Require at least one `--path` for `audit`, `audit-prompt`, and `guard`.
- [x] Support `--exclude-path` for watched trees.
- [x] Support a configurable policy path through `--config`, falling back to the default user config path when present.
- [x] Deploy the release binary, local policy config, and selected audit or guard systemd service through `deploy.sh`; stop the enforcing service before replacing its protected policy, restore service availability if privileged installation fails, then restart into the selected mode.

## How it works

- [System design](../wiki/systems/config-guard.md)
- [Policy model](../wiki/systems/config-guard-policy.md)
- [Audit learning](../wiki/systems/config-guard-learning.md)
- [Reconcile workflow](../wiki/systems/config-guard-reconcile.md)

## Implementation inventory

- `src/main.rs` - CLI command parsing and command wiring for audit, audit-prompt, guard, reconcile, and prompt testing.
- `src/fanotify.rs` - mode-specific fanotify setup, mount/tree marking, scope filtering, overflow handling, and guard responses.
- `src/fanotify/guard.rs` - guard-mode event servicing, prompt coordination, and permission-event completion.
- `src/fanotify/audit.rs` - audit and audit-prompt open-identity capture, close-event classification, policy evaluation, learning, and logging orchestration.
- `src/fanotify/prompt_resolution.rs` - prompt decision caching, graphical-session detection, and prompt resolution.
- `src/fanotify/audit_identity.rs` - bounded PID/object-identity queues bridging audit open and close events across path renames.
- `src/fanotify/audit_process.rs` - bounded TTL cache of executable identities keyed by pidfd process generation for processes too short-lived for procfs inspection.
- `src/fanotify/event.rs` - fanotify metadata parsing, pidfd process-generation extraction, event target/object identity, and descriptor cleanup.
- `src/fanotify/watch.rs` - audit mount marks and guard tree-mark installation.
- `src/policy.rs` - policy config types, subject matching, ownership checks, sensitive-path checks, shared-path checks, and prompt decisions.
- `src/process.rs` - `/proc` process inspection, process subject extraction, command parsing, ancestor discovery, and Wayland/logind session environment reads.
- `src/prompt.rs` - authd and command prompt adapters plus timeout and exit-status decision mapping.
- `src/systemd_notify.rs` - systemd readiness notification transport and socket addressing.
- `src/learning.rs` - audit observation aggregation and learned TOML output for candidate owned paths.
- `src/reconcile.rs` - config-home inventory, association/archive planning, and apply-mode config/archive updates.
- `src/lib.rs` - public module exports for integration tests.
- `config/osso.toml` - local policy used by the deployed audit service.
- `config/config-guard.service` - default audit-mode systemd unit.
- `config/config-guard-guard.service` - explicit enforcement-mode systemd unit.
- `deploy.sh` - release build and explicit audit/guard install path for the binary, policy, and selected service file.
- `run-tests.sh` - project verification script.

## Tests asserting this spec

- `tests/policy.rs` - policy decisions, including exact `.gitignore` access precedence, strict non-owner denial precedence, and TOML parsing.
- `tests/root_integration.rs` - privileged fanotify enforcement, including one-prompt reuse across scopes for one process generation, stale queued-prompt suppression after process exit, re-prompting for a new generation, strict non-owner denial without prompt fallback, and prompt-helper reads from watched unprotected files without deadlock.
- `tests/process_identity.rs` - process identity parsing contract.
- `tests/learning.rs` - audit learning root selection and alias mapping.
- `tests/reconcile.rs` - reconcile planning and apply behavior.
- `tests/config_file.rs` - local `config/osso.toml` policy expectations, including ancestry-scoped `sqlite3` and `systemd-executor` access to Firefox backup data.
- `tests/deployment.rs` - static audit-mode unit and deploy activation-script contract.
- `src/fanotify.rs` unit tests - mode masks, merged close classification, overflow handling, scope filtering, unknown-subject evaluation, directory walking, and excluded-tree behavior.
- `src/fanotify/audit_identity.rs` unit tests - queued identities, bounded eviction, PID-generation replacement, take-on-close, and failed-open invalidation.
- `src/fanotify/audit_process.rs` unit tests - exec-identity TTL, capacity eviction, dynamic-loader handling, pidfs validation, and pidfd generation isolation.
- `src/systemd_notify.rs` unit tests - readiness message delivery over the systemd notification socket.
- `src/main.rs` unit tests - authd service timeout defaults for prompt-capable commands.
- `src/process.rs` unit tests - target Wayland/logind session environment selection.

## Known gaps (current cycle)

- [ ] Add machine-checkable coverage for the CLI subcommand surface and default config-path behavior.
- [x] Complete audit burn-in, add durable observed workflow rules, and enable guard only through an explicit deployment choice.
- [ ] Add a policy review checklist for turning observed audit lines into durable allow rules, including the "no ad hoc cp allow" rule.

## Out of scope

- Kernel fanotify semantics beyond the event types Config Guard consumes.
- Prompt UI design beyond the request/decision contract exposed through `prompt.rs`.
- Full host policy for machines other than the local `osso` profile in `config/osso.toml`.
- Automatically switching from audit mode to guard mode; enforcement remains a deliberate post-burn-in decision.
- Race-free coverage of directories created after guard-mode startup; guard currently uses inode tree marks.
- Pre-write denial based on write-specific policy; `FAN_CLOSE_WRITE` reports writes only after they complete.
