# Config Guard

Config Guard watches sensitive configuration trees with Linux fanotify and evaluates each access against `config/osso.toml`.

## Runtime modes

- `audit` logs policy violations as `FORBID audit` and always lets the access continue. Its service creates the `/run/config-guard` runtime directory but does not create the `enforcing` marker.
- `audit-prompt` uses the same prompt backend as guard, logs policy violations as `FORBID audit` and the resulting user/default decision as `FORBID audit-prompt`, and always lets the access continue. Use it to validate the dialog before enforcement.
- `guard` logs policy violations as `FORBID guard`, resolves them through authd or a configured prompt command, then permits or denies the event. While a prompt is active, guard continues servicing watched-path permission events needed by the prompt workflow, so helpers can load watched files without deadlocking the original access. Its service wants `secrets-broker.service` and creates `/run/config-guard/enforcing` only after Config Guard reports systemd readiness. The marker is a readiness/mode signal, not the credential-store permission boundary.

## Monitoring scope versus ownership scope

The service's `--path` arguments define fanotify observation roots. They are intentionally broad so audit and guard can observe accesses across the configured filesystem areas. They do not create policy ownership for every descendant.

Ownership protection comes only from explicit `owned_paths` entries (and access sharing from explicit `shared_paths` entries). A generic descendant under a monitored root such as `/etc`, `/var/lib`, `/var/log`, `$HOME/.local/share`, or `$HOME/.local/state` is unowned when no explicit policy rule matches it, so ordinary access is allowed by the ownership policy. Other rules, such as sensitive-path or dev-tool rules, can still produce a prompt. The `$HOME/.config/config-guard` directory is owned, but its exact `config.toml` file is an explicit read-only shared path for all subjects: readers do not prompt, while writes to that file and reads or writes to adjacent files remain protected by the owned directory. This avoids repeated `CrossOwnerRead` prompts when distinct verification reader processes inspect the policy without granting those processes config-guard directory access. The policy allows `syncthing-cli` as a subject for both `$HOME/.config/syncthing-cli` and `$HOME/.config/syncthing`.

The deployed policy also shares the repeatable Noctalia Niri include workflow: `cp` and `sed` may read and write `$HOME/.config/niri/noctalia.kdl`, while `grep` may read `$HOME/.config/niri/config.kdl`. These narrow rules let Noctalia regenerate its Niri include without repeated cross-owner prompts; they do not make the surrounding `$HOME/.config/niri` tree shared.

As a policy precedence exception, any access kind to a path whose final component is exactly `.gitignore` is allowed before ownership, non-owner denial, shared-path, sensitive-path, or prompt evaluation. Names such as `.gitignore.lock` do not match this exception and remain governed normally.

A temporary tracked-credential exception allows subject `git` to read only `$HOME/.config/gc` and `$HOME/.config/gmail-cli`, because those credential files are intentionally tracked in the Provisioning repository. This exception does not allow Git helpers or broader sensitive-configuration access. Retire it when tracked credential storage is replaced by a workflow that does not require Git to open these files.

`/etc/NetworkManager/dispatcher.d` and its descendants are an explicit all-subject, all-access shared subtree, so they are unprotected by policy. The parent `/etc/NetworkManager` and sibling subtrees remain governed by their existing ownership rules.

An owned path may set `deny_non_owner = true`. Its configured owner and allowed subjects still receive access, but every other subject receives `Deny` before shared-path, sensitive-path, prompt, cache, or fail-open handling. Use this only as defense-in-depth for data whose Unix ownership already provides the primary fail-closed boundary; fanotify enforcement disappears if Config Guard stops.

The deployed policy applies this strict rule to `/var/lib/secrets-broker`: owner `secrets-broker`, explicit additional subject `secrets-broker-admin`, and `deny_non_owner = true`. Other subjects cannot reach the credential store through prompt or fail-open handling; Unix ownership remains the primary boundary if Config Guard is stopped.

The deployed policy strictly owns `$HOME/.config/curseforge` for the `curseforge` executable with no additional allowed subjects and `deny_non_owner = true`. The credential directory should use Unix mode `0700` and its credential file mode `0600`; those Unix permissions are the primary at-rest boundary, not encryption, and Config Guard does not set or validate them. Config Guard adds executable-path enforcement. The service runs in guard mode with global `fail_open = true`; this rule returns `Deny` before prompt or fail-open handling for non-owner access, except for the global final-component `.gitignore` allow rule. Sibling paths such as `$HOME/.config/curseforge-helper` remain governed independently.

The deployed policy removed broad ownership entries for `/etc`, `/var`, `/var/log`, `$HOME/.local/share`, and `$HOME/.local/state`, and intentionally leaves `$HOME/.local/share/uv` unowned. Explicit sibling subtrees under `$HOME/.local/share` remain protected when listed in `owned_paths` or another applicable policy section. Add a specific entry when a new directory must receive ownership protection; adding a directory to a monitored root alone is not sufficient.

The local policy lets `firefox` read `$HOME/.config/dconf` and lets `crashhelper` read and write `$HOME/.config/firefox` so normal startup does not wait on guard prompts. It also explicitly owns `$HOME/.local/share/firefox-backup` for `firefox-profile-backup`. The existing `sqlite3` helper is allowed only when `firefox-profile-backup` is an ancestor, and `systemd-executor` only when `systemd` is an ancestor; either executable without its required ancestor remains subject to the normal prompt decision.

Audit and guard use different fanotify strategies:

- **Audit mode** canonicalizes configured roots and exclusions, expands watched configuration roots with the resolved targets of direct symlink children under `$HOME/.config`, installs non-blocking mount notification marks for every resulting root, then filters received paths against that canonical scope. This lets accesses through logical paths such as `~/.config/gh` remain observable when their files live under `/syncthing`. Mount marks cover directories created or moved into scope after startup without the race inherent in recursive inode marks. They apply only to the mount that exists when the mark is installed: mounts created after startup are not covered, so restart Config Guard after adding a submount beneath a watched root. `FAN_REPORT_PIDFD` binds executable fallback identities to a kernel process generation rather than a reusable PID. Config Guard rejects pidfd information that is not backed by pidfs instead of risking cross-process attribution. `FAN_OPEN_EXEC` records that identity in a bounded 30-second cache; `FAN_OPEN` captures the fuller procfs identity in a bounded queue keyed by PID and file object identity (device and inode), so a rename between open and close does not break pairing. Close handling consumes the matching open identity, falls back to the recent exec identity only for the same pidfd generation, then finally evaluates an explicit unknown subject if neither identity source succeeds. Config Guard also rejects fanotify event metadata versions it does not understand. `FAN_CLOSE_NOWRITE` is classified as read and `FAN_CLOSE_WRITE` as write. If both bits occur in one merged kernel event, both classifications are evaluated. The kernel may coalesce duplicate notification events, so audit-line counts are evidence of delivered access kinds, not exact close or file-descriptor counts.
- **Guard mode** uses `FAN_OPEN_PERM` inode-tree marks so an open can be allowed or denied before access. Resolved `$HOME/.config` symlink targets are added as explicit roots; the directory walk itself still does not follow symlinks. It intentionally does not use `FAN_ACCESS_PERM`, which would repeat decisions for individual read syscalls. The open decision has no write-intent classification: it can block an unapproved process before it opens a file, but `FAN_CLOSE_WRITE` arrives only after a permitted write completes, so Config Guard cannot enforce a write-specific denial at close. Guard also does not add marks for directories created after startup.

Audit requests an unlimited kernel event queue because the service runs with `CAP_SYS_ADMIN`, and any reported queue overflow or invalid event descriptor terminates the process. systemd then restarts it; coverage loss is never silently accepted.

Prompt answers are cached by verified process generation (PID, process start time, and executable), access kind, and decision reason rather than policy scope. One process scanning multiple protected roots therefore receives one prompt for equivalent reads; both Allow and Deny answers apply only to that process generation. For a cross-owner helper, Config Guard searches its ordered process ancestors for the nearest verified ancestor whose executable basename is configured as an owner anywhere in policy; the selected ancestor need not own the particular protected scope being accessed. An explicit Allow then creates a runtime-only ancestry authorization keyed by the exact verified helper executable path and exact verified configured-owner ancestor executable path. That authorization applies across all Config Guard protected scopes, including scopes with a different configured owner, and all later process generations and logical Pi sessions using that exact pair until Config Guard restarts. A different helper path or different ancestor executable path does not reuse it, even when the executable basenames match. The absence of a configured-owner ancestor, an unverified ancestry chain, explicit Deny, default decisions, missing verified executable identity, and Config Guard restart do not create or reuse ancestry authorization. Before the serialized prompt worker presents each queued dialog, it rereads the process start time from procfs. A missing process or changed start time discards that stale dialog and applies the configured default to its pending events, so killing a blocked process cannot leave later prompts queued behind it. If process inspection cannot provide the required executable and process-generation identity, Config Guard logs the identity failure, evaluates policy using the available or explicit `unknown` subject, and does not cache the ordinary prompt answer or create ancestry authorization without both verified executable paths.

Deployment defaults to `audit`. Passing `--mode guard` installs the guard unit after an explicit post-burn-in decision. `audit-prompt` remains a manual diagnostic mode and is never installed as the system service.

## Testing the session dialog

Run `test-prompt` for one direct authd/session-dialog request, or run `audit-prompt` against a temporary scope. The latter logs `user_decision=...` but never enforces the decision.

## Deployment

Run `./deploy.sh` from the repository root for audit mode, or `./deploy.sh --mode guard` for enforcement. It:

1. Validates the selected mode before building or changing host state.
2. Builds and installs the release binary to `~/.cargo/bin/config-guard`.
3. Requires `HOME=/home/osso`, then uses one pooled `authsudo` invocation for the protected installation phase. That phase stops the existing service, installs `config/osso.toml` to `/home/osso/.config/config-guard/config.toml` as `osso:osso` with mode `0600`, and restores service availability if a later installation step fails. Stopping first prevents the enforcing daemon from blocking replacement of its own policy.
4. The same privileged phase installs the audit or guard unit under `/etc/systemd/system/config-guard.service`, reloads systemd, enables it at boot, and restarts it in the selected mode. The guard unit wants `secrets-broker.service`; the audit unit has no such dependency. Both scopes explicitly include `~/.ssh` and `~/.kube`; monitoring scope remains distinct from policy ownership, with `~/.kube` owned by `kubectl` and `flux` listed as an explicit allowed subject.
5. Keeps the build and post-restart health checks unprivileged.
6. Relies on `Type=notify`: `systemctl restart` does not complete until the daemon sends `READY=1`, which happens only after all monitoring marks are installed. Guard's `ExecStartPost` creates `/run/config-guard/enforcing` only after that readiness point; audit has no marker step.
7. Waits six additional seconds, then verifies boot enablement, active state, `Type=notify`, the selected-mode `ExecStart`, a nonzero main PID, zero restarts, and marker presence in guard mode or absence in audit mode.

Deployment fails if any bounded post-restart check fails. This proves initialized startup health and short-window stability, not long-term stability or policy completeness.

### Verified deployment state

`verified: 2026-08-14`

- Deployed revision: `e4dea7e13455e95d4b585c51cd7b7b893066c462`.
- `config-guard.service` is active and running in guard mode after one intentional restart; `MainPID=132425`, `NRestarts=0`, and `/run/config-guard/enforcing` is present.
- Installed policy SHA-256 is `c300e711cc94ed8a9cab62af1fccbd643e85f6e241187f6a9da1cafcd4531196`, matching the source policy; the installed policy contains `/home/osso/.config/curseforge`.
- Privileged root integration `guard_denies_strict_non_owner_without_prompt_fallback` passed `1/1`.
- The full non-root runner passed; 18 privileged tests were ignored in that run.

## Service verification

Use read-only checks after deployment:

```text
systemctl is-enabled config-guard.service
systemctl is-active config-guard.service
systemctl show config-guard.service -p Type -p ExecStart -p ExecMainStatus -p MainPID -p NRestarts -p ActiveState -p SubState
journalctl -u config-guard.service -b
```

Expected state: `enabled`, `active`, `Type=notify`, nonzero `MainPID`, `NRestarts=0`, and an `ExecStart` matching the selected mode. Guard mode additionally requires `/run/config-guard/enforcing`; audit mode requires that marker to be absent. These checks describe deployment verification, not proof that either mode is currently live.

During audit burn-in, review `FORBID audit` entries. Guard violations are logged as `FORBID guard`; audit labels do not indicate the active runtime mode. Add durable policy allows only for stable owners or repeatable workflows; do not encode one-off copy commands.

## Guard transition and rollback

Before running `./deploy.sh --mode guard`:

1. Complete an audit burn-in with normal workloads.
2. Review repeated violations and update policy intentionally.
3. Run privileged fanotify integration tests, including an explicit denied open.
4. Accept that `fail_open = true` allows accesses when prompting fails or no graphical session is available. The deployed unit uses authd, whose graphical prompt is skipped without `WAYLAND_DISPLAY` and therefore uses the configured default. Guard mode is enforcement-capable, not strict fail-closed enforcement. The explicit `/var/lib/secrets-broker` `deny_non_owner` rule remains earlier than prompt and fail-open handling, so non-owner credential-store access is denied without invoking that fallback.
5. If `--prompt-command` is supplied for a manual guard run, it runs even without a graphical session: exit status 0 allows, exit status 1 denies, and a start failure, timeout, or other status uses the configured default. The deployed guard unit does not supply `--prompt-command`.
6. Accept the current coverage limits: directories created after startup are not marked, and write-specific classification arrives only after a permitted write closes.

After deployment, verify the selected `ExecStart`, exercise controlled allowed and denied reads, and inspect service health. Roll back without editing system files manually:

```text
./deploy.sh --mode audit
```

Rollback rebuilds and reinstalls the current binary and policy, replaces the unit with `config/config-guard.service`, restarts the service, and verifies audit mode.
