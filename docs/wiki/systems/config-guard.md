# Config Guard

Config Guard watches sensitive configuration trees with Linux fanotify and evaluates each access against `config/osso.toml`.

## Runtime modes

- `audit` logs policy violations as `FORBID audit` and always lets the access continue.
- `guard` resolves policy violations through authd or a configured prompt command, then permits or denies the event.

Read policy is evaluated once on `FAN_OPEN_PERM`; Config Guard does not subscribe to `FAN_ACCESS_PERM`, which would repeat the same decision for each `read()` syscall. Writes are observed through `FAN_CLOSE_WRITE`. That provides accurate audit evidence after a write, but the close event is too late to deny a write based only on write-specific policy; guard-mode transition review must account for this limitation.

The installed systemd unit runs `audit`. Switching to `guard` is a deliberate post-burn-in change, not part of normal deployment.

## Deployment

Run `./deploy.sh` from the repository root. It:

1. Builds and installs the release binary to `~/.cargo/bin/config-guard`.
2. Requires `HOME=/home/osso` and installs `config/osso.toml` to `/home/osso/.config/config-guard/config.toml` with mode `0600`, matching the systemd unit exactly.
3. Installs `config/config-guard.service` under `/etc/systemd/system`.
4. Reloads systemd, enables the service at boot, and restarts it.
5. Waits three seconds, then verifies boot enablement, active state, audit-mode `ExecStart`, and a nonzero main PID.

Deployment fails if any bounded post-restart check fails. This proves immediate startup health, not long-term stability or policy completeness.

## Audit verification

Use read-only checks after deployment:

```text
systemctl is-enabled config-guard.service
systemctl is-active config-guard.service
systemctl show config-guard.service -p ExecStart -p ExecMainStatus -p MainPID -p ActiveState -p SubState
journalctl -u config-guard.service -b
```

Expected state: `enabled`, `active`, nonzero `MainPID`, and an audit-mode `ExecStart`.

Review `FORBID audit` entries during burn-in. Add durable policy allows only for stable owners or repeatable workflows; do not encode one-off copy commands.

## Guard transition

Before changing the unit from `audit` to `guard`:

1. Complete an audit burn-in with normal workloads.
2. Review repeated violations and update policy intentionally.
3. Decide whether `fail_open = true` remains acceptable. Current policy defaults to allow on prompt errors and for accesses without a graphical session, so guard mode is not strict fail-closed enforcement.
4. Run privileged fanotify integration tests.
5. Deploy, exercise a controlled cross-owner access, and inspect service logs.
