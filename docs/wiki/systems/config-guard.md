# Config Guard

Config Guard watches sensitive configuration trees with Linux fanotify and evaluates each access against `config/osso.toml`.

## Runtime modes

- `audit` logs policy violations as `FORBID audit` and always lets the access continue.
- `guard` resolves policy violations through authd or a configured prompt command, then permits or denies the event.

Audit and guard use different fanotify strategies:

- **Audit mode** canonicalizes configured roots and exclusions, installs non-blocking mount notification marks for every configured root, then filters received paths against that canonical scope. Mount marks cover directories created or moved into scope after startup without the race inherent in recursive inode marks. `FAN_REPORT_PIDFD` binds executable fallback identities to a kernel process generation rather than a reusable PID. `FAN_OPEN_EXEC` records that identity in a bounded 30-second cache; `FAN_OPEN` captures the fuller procfs identity in a bounded queue keyed by PID and file object identity (device and inode), so a rename between open and close does not break pairing. Close handling consumes the matching open identity, falls back to the recent exec identity only for the same pidfd generation, then finally evaluates an explicit unknown subject if neither identity source succeeds. `FAN_CLOSE_NOWRITE` is classified as read and `FAN_CLOSE_WRITE` as write. If both bits occur in one merged kernel event, both classifications are evaluated. The kernel may coalesce duplicate notification events, so audit-line counts are evidence of delivered access kinds, not exact close or file-descriptor counts.
- **Guard mode** uses `FAN_OPEN_PERM` inode-tree marks so an open can be allowed or denied before access. It intentionally does not use `FAN_ACCESS_PERM`, which would repeat decisions for individual read syscalls. The open decision has no write-intent classification: it can block an unapproved process before it opens a file, but `FAN_CLOSE_WRITE` arrives only after a permitted write completes, so Config Guard cannot enforce a write-specific denial at close. Guard also does not add marks for directories created after startup.

Audit requests an unlimited kernel event queue because the service runs with `CAP_SYS_ADMIN`, and any reported queue overflow or invalid event descriptor terminates the process. systemd then restarts it; coverage loss is never silently accepted.

If process inspection fails, Config Guard logs the identity failure and evaluates policy using an explicit `unknown` subject. Unknown identities are not eligible for prompt-decision caching.

The installed systemd unit runs `audit`. Switching to `guard` is a deliberate post-burn-in change, not part of normal deployment.

## Deployment

Run `./deploy.sh` from the repository root. It:

1. Builds and installs the release binary to `~/.cargo/bin/config-guard`.
2. Requires `HOME=/home/osso` and installs `config/osso.toml` to `/home/osso/.config/config-guard/config.toml` with mode `0600`, matching the systemd unit exactly.
3. Uses one pooled `authsudo` invocation to install `config/config-guard.service` under `/etc/systemd/system`, reload systemd, enable the audit service at boot, and restart it. Deployment never enables or starts guard mode.
4. Keeps build, user configuration install, and post-restart health checks unprivileged.
5. Relies on `Type=notify`: `systemctl restart` does not complete until the daemon sends `READY=1`, which happens only after all monitoring marks are installed.
6. Waits six additional seconds, then verifies boot enablement, active state, `Type=notify`, audit-mode `ExecStart`, a nonzero main PID, and zero restarts.

Deployment fails if any bounded post-restart check fails. This proves initialized startup health and short-window stability, not long-term stability or policy completeness.

## Audit verification

Use read-only checks after deployment:

```text
systemctl is-enabled config-guard.service
systemctl is-active config-guard.service
systemctl show config-guard.service -p Type -p ExecStart -p ExecMainStatus -p MainPID -p NRestarts -p ActiveState -p SubState
journalctl -u config-guard.service -b
```

Expected state: `enabled`, `active`, `Type=notify`, nonzero `MainPID`, `NRestarts=0`, and an audit-mode `ExecStart`.

Review `FORBID audit` entries during burn-in. Add durable policy allows only for stable owners or repeatable workflows; do not encode one-off copy commands.

## Guard transition

Before changing the unit from `audit` to `guard`:

1. Complete an audit burn-in with normal workloads.
2. Review repeated violations and update policy intentionally.
3. Decide whether `fail_open = true` remains acceptable. Current policy defaults to allow on prompt errors and for accesses without a graphical session, so guard mode is not strict fail-closed enforcement.
4. Resolve guard's current limitations: new directories are not dynamically marked, and write-specific decisions occur after the write closes.
5. Run privileged fanotify integration tests.
6. Deploy, exercise controlled cross-owner reads and writes, and inspect service logs.
