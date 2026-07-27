# Config Guard

Config Guard watches sensitive configuration trees with Linux fanotify and evaluates each access against `config/osso.toml`.

## Runtime modes

- `audit` logs policy violations as `FORBID audit` and always lets the access continue.
- `audit-prompt` uses the same prompt backend as guard, logs policy violations as `FORBID audit` and the resulting user/default decision as `FORBID audit-prompt`, and always lets the access continue. Use it to validate the dialog before enforcement.
- `guard` logs policy violations as `FORBID guard`, resolves them through authd or a configured prompt command, then permits or denies the event.

## Monitoring scope versus ownership scope

The service's `--path` arguments define fanotify observation roots. They are intentionally broad so audit and guard can observe accesses across the configured filesystem areas. They do not create policy ownership for every descendant.

Ownership protection comes only from explicit `owned_paths` entries (and access sharing from explicit `shared_paths` entries). A generic descendant under a monitored root such as `/etc`, `/var/lib`, `/var/log`, `$HOME/.local/share`, or `$HOME/.local/state` is unowned when no explicit policy rule matches it, so ordinary access is allowed by the ownership policy. Other rules, such as sensitive-path or dev-tool rules, can still produce a prompt. The policy allows `syncthing-cli` as a subject for both `$HOME/.config/syncthing-cli` and `$HOME/.config/syncthing`.

The deployed policy removed broad ownership entries for `/etc`, `/var`, `/var/log`, `$HOME/.local/share`, and `$HOME/.local/state`. Sensitive subdirectories remain protected by listing those directories explicitly in `owned_paths` or another applicable policy section. Add a specific entry when a new directory must receive ownership protection; adding a directory to a monitored root alone is not sufficient.

Audit and guard use different fanotify strategies:

- **Audit mode** canonicalizes configured roots and exclusions, expands watched configuration roots with the resolved targets of direct symlink children under `$HOME/.config`, installs non-blocking mount notification marks for every resulting root, then filters received paths against that canonical scope. This lets accesses through logical paths such as `~/.config/gh` remain observable when their files live under `/syncthing`. Mount marks cover directories created or moved into scope after startup without the race inherent in recursive inode marks. They apply only to the mount that exists when the mark is installed: mounts created after startup are not covered, so restart Config Guard after adding a submount beneath a watched root. `FAN_REPORT_PIDFD` binds executable fallback identities to a kernel process generation rather than a reusable PID. Config Guard rejects pidfd information that is not backed by pidfs instead of risking cross-process attribution. `FAN_OPEN_EXEC` records that identity in a bounded 30-second cache; `FAN_OPEN` captures the fuller procfs identity in a bounded queue keyed by PID and file object identity (device and inode), so a rename between open and close does not break pairing. Close handling consumes the matching open identity, falls back to the recent exec identity only for the same pidfd generation, then finally evaluates an explicit unknown subject if neither identity source succeeds. Config Guard also rejects fanotify event metadata versions it does not understand. `FAN_CLOSE_NOWRITE` is classified as read and `FAN_CLOSE_WRITE` as write. If both bits occur in one merged kernel event, both classifications are evaluated. The kernel may coalesce duplicate notification events, so audit-line counts are evidence of delivered access kinds, not exact close or file-descriptor counts.
- **Guard mode** uses `FAN_OPEN_PERM` inode-tree marks so an open can be allowed or denied before access. Resolved `$HOME/.config` symlink targets are added as explicit roots; the directory walk itself still does not follow symlinks. It intentionally does not use `FAN_ACCESS_PERM`, which would repeat decisions for individual read syscalls. The open decision has no write-intent classification: it can block an unapproved process before it opens a file, but `FAN_CLOSE_WRITE` arrives only after a permitted write completes, so Config Guard cannot enforce a write-specific denial at close. Guard also does not add marks for directories created after startup.

Audit requests an unlimited kernel event queue because the service runs with `CAP_SYS_ADMIN`, and any reported queue overflow or invalid event descriptor terminates the process. systemd then restarts it; coverage loss is never silently accepted.

If process inspection fails, Config Guard logs the identity failure and evaluates policy using an explicit `unknown` subject. Unknown identities are not eligible for prompt-decision caching.

Deployment defaults to `audit`. Passing `--mode guard` installs the guard unit after an explicit post-burn-in decision. `audit-prompt` remains a manual diagnostic mode and is never installed as the system service.

## Testing the session dialog

Run `test-prompt` for one direct authd/session-dialog request, or run `audit-prompt` against a temporary scope. The latter logs `user_decision=...` but never enforces the decision.

## Deployment

Run `./deploy.sh` from the repository root for audit mode, or `./deploy.sh --mode guard` for enforcement. It:

1. Validates the selected mode before building or changing host state.
2. Builds and installs the release binary to `~/.cargo/bin/config-guard`.
3. Requires `HOME=/home/osso` and installs `config/osso.toml` to `/home/osso/.config/config-guard/config.toml` with mode `0600`, matching the systemd unit exactly.
4. Uses one pooled `authsudo` invocation to install the audit or guard unit under `/etc/systemd/system/config-guard.service`, reload systemd, enable it at boot, and restart it. Both scopes explicitly include `~/.ssh` and `~/.kube`; monitoring scope remains distinct from policy ownership, with `~/.kube` owned by `kubectl` and `flux` listed as an explicit allowed subject.
5. Keeps build, user configuration install, and post-restart health checks unprivileged.
6. Relies on `Type=notify`: `systemctl restart` does not complete until the daemon sends `READY=1`, which happens only after all monitoring marks are installed.
7. Waits six additional seconds, then verifies boot enablement, active state, `Type=notify`, the selected-mode `ExecStart`, a nonzero main PID, and zero restarts.

Deployment fails if any bounded post-restart check fails. This proves initialized startup health and short-window stability, not long-term stability or policy completeness.

## Service verification

Use read-only checks after deployment:

```text
systemctl is-enabled config-guard.service
systemctl is-active config-guard.service
systemctl show config-guard.service -p Type -p ExecStart -p ExecMainStatus -p MainPID -p NRestarts -p ActiveState -p SubState
journalctl -u config-guard.service -b
```

Expected state: `enabled`, `active`, `Type=notify`, nonzero `MainPID`, `NRestarts=0`, and an `ExecStart` matching the selected mode.

During audit burn-in, review `FORBID audit` entries. Guard violations are logged as `FORBID guard`; audit labels do not indicate the active runtime mode. Add durable policy allows only for stable owners or repeatable workflows; do not encode one-off copy commands.

## Guard transition and rollback

Before running `./deploy.sh --mode guard`:

1. Complete an audit burn-in with normal workloads.
2. Review repeated violations and update policy intentionally.
3. Run privileged fanotify integration tests, including an explicit denied open.
4. Accept that `fail_open = true` allows accesses when prompting fails or no graphical session is available. The deployed unit uses authd, whose graphical prompt is skipped without `WAYLAND_DISPLAY` and therefore uses the configured default. Guard mode is enforcement-capable, not strict fail-closed enforcement.
5. If `--prompt-command` is supplied for a manual guard run, it runs even without a graphical session: exit status 0 allows, exit status 1 denies, and a start failure, timeout, or other status uses the configured default. The deployed guard unit does not supply `--prompt-command`.
6. Accept the current coverage limits: directories created after startup are not marked, and write-specific classification arrives only after a permitted write closes.

After deployment, verify the selected `ExecStart`, exercise controlled allowed and denied reads, and inspect service health. Roll back without editing system files manually:

```text
./deploy.sh --mode audit
```

Rollback rebuilds and reinstalls the current binary and policy, replaces the unit with `config/config-guard.service`, restarts the service, and verifies audit mode.
