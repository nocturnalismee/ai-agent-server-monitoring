# Service Monitoring Redesign

Date: 2026-10-27
Status: Draft for review
Owner: server_agent

## Problem

Service health checking is fragile:

1. Unit aliases are not resolved. `ssh` vs `sshd`, `apache2` vs `httpd`,
   `mysql` vs `mariadb`/`mysqld`, `exim` vs `exim4` are treated as different
   services. A monitored alias can be reported missing while the real unit is
   healthy.
2. `install.sh` snapshots only services that are *active at install time*.
   A service that happens to be stopped during installation is omitted
   permanently.
3. `unknown` (systemctl missing, timeout, permission) and `not-found` are
   conflated. With the default `ALERT_ON_MISSING_SERVICE=false`, a required
   service that cannot be inspected is silently skipped.
4. There is no required/optional distinction. A missing optional component and
   a dead required daemon are treated identically.
5. No flap protection. A quickly restarting service produces repeated
   CRITICAL/recovery pairs.
6. Evidence collection only runs `journalctl -u <name>`. When the unit alias is
   wrong, the journal lookup is empty, and there is no `systemctl status`
   snapshot.
7. `COMMON_SERVICES` does not model panel daemons (cPanel, CyberPanel, aaPanel,
   Plesk, DirectAdmin, HestiaCP, CloudPanel, RunCloud).

## Goals

- Per-panel default service profiles with clear required/optional semantics.
- Environment overrides that are simple and backward compatible.
- Robust unit discovery and alias resolution using systemd itself.
- Correct severity for missing vs inactive vs failed vs unknown.
- Anti-flap protection with a configurable consecutive-failure threshold.
- Useful evidence: resolved unit, `systemctl status`, and journal.
- `--check-config` shows the final resolved service lists.
- Existing `SERVICES` installs keep working.

## Non-goals

- Dependency-aware service checks (`Requires=`/`After=` traversal).
- Port/HTTP probes. This remains a service-state monitor.
- Automatic enabling/disabling/restarting of services (the agent stays
  read-only).
- Reworking non-service monitors.

## Configuration

New fields:

| Key | Default | Meaning |
| :--- | :---: | :--- |
| `SERVICE_PROFILE` | `auto` | `auto`, `none`, or a panel profile name. |
| `SERVICES_REQUIRED` | _(unset)_ | Explicit required list; overrides the profile required list. |
| `SERVICES_OPTIONAL` | _(unset)_ | Explicit optional list; overrides the profile optional list. |
| `SERVICE_FAILURE_THRESHOLD` | `2` | Consecutive non-active cycles before an inactive service alerts. `failed` alerts immediately. |

Existing keys retained:

- `SERVICES` (legacy): when non-empty, it is treated as the required list and
  fully overrides the profile.
- `AUTO_DETECT_SERVICES`: applies only to the legacy `SERVICES` behavior
  (filter to installed units). Profile targets are never filtered out, so a
  missing required service can be reported.
- `ALERT_ON_MISSING_SERVICE`: retained for `unknown` states and optional
  services. See severity rules.

### Precedence (highest first)

1. `SERVICES` (legacy) non-empty -> required list; optional list empty.
2. `SERVICES_REQUIRED` non-empty -> required list.
3. `SERVICES_OPTIONAL` non-empty -> optional list.
4. `SERVICE_PROFILE`:
   - `auto` -> profile for the detected panel, or `standalone` when no panel is
     detected.
   - `none` -> no built-in defaults (env lists only).
   - an explicit profile name -> that profile.
5. Fields not overridden keep the profile defaults.

`SERVICES_REQUIRED` and `SERVICES_OPTIONAL` are independent: setting one does
not clear the other. If a name appears in both, validation fails (ambiguous
intent).

Example (cPanel):

```env
SERVICE_PROFILE=auto
SERVICES_REQUIRED=httpd,mysql,exim,dovecot,cpanel
SERVICES_OPTIONAL=redis,php-fpm
```

Legacy example (still takes precedence over profiles):

```env
SERVICES=nginx,mysql
AUTO_DETECT_SERVICES=true
```

## Built-in profiles

Profile names match `EnvironmentDetector` panel names, lowercased:
`standalone`, `cpanel`, `cyberpanel`, `aapanel`, `plesk`, `directadmin`,
`hestiacp`, `vestacp`, `cloudpanel`, `runcloud`, `none`. The `vestacp` and
`vesta` panel tokens both select the `vestacp` profile.

| Profile | Required | Optional |
| :--- | :--- | :--- |
| standalone | ssh | nginx, apache2, httpd, mysql, redis, docker |
| cpanel | cpanel, mysql, exim, dovecot | named, httpd, lsws, cphulkd, pure-ftpd, clamd, spamd, redis, php-fpm |
| cyberpanel | lscpd, lsws, mariadb | postfix, pure-ftpd, dovecot, powerdns, redis, php-fpm |
| aapanel | bt, mysql | nginx, httpd, apache2, php-fpm, redis, pure-ftpd, postgresql |
| plesk | sw-cp-server, sw-engine, psa | nginx, apache2, httpd, postfix, dovecot, mysql, redis, php-fpm |
| directadmin | directadmin | httpd, nginx, apache2, exim, dovecot, mysql, php-fpm, redis |
| hestiacp | hestia | nginx, apache2, exim, dovecot, mysql, named, vsftpd, php-fpm, redis |
| vestacp | vesta | nginx, apache2, exim, dovecot, mysql, named, vsftpd, php-fpm, redis |
| cloudpanel | clp-nginx, clp-php-fpm | mysql, redis |
| runcloud | nginx | php-fpm, mysql, redis |
| none | _(empty)_ | _(empty)_ |

Alias groups absorb the variants: `mysql` resolves to `mariadb`/`mysqld`,
`named` to `bind9`, `exim` to `exim4`, `apache2` to `httpd`, `ssh` to `sshd`,
`redis` to `redis-server`, `powerdns` to `pdns`. List only one canonical member
per alias group in a profile to avoid duplicate checks.

Rationale: required entries are the panel's control plane plus its core data
and mail services. Alternative web servers and optional tooling are listed as
optional so a deliberate LiteSpeed/Nginx choice does not produce a false
CRITICAL. A dead optional service still produces WARNING.

## Unit discovery and alias resolution

New module `server_agent/detectors/service_profiles.py` owns profile data and
the alias map. `ServiceDetector` owns systemd interaction.

Alias groups (first resolvable member wins):

- `ssh`, `sshd`
- `apache2`, `httpd`, `apache`
- `mysql`, `mariadb`, `mysqld`
- `exim`, `exim4`
- `named`, `bind9`, `named-chroot`
- `redis`, `redis-server`
- `powerdns`, `pdns`

Resolution for a configured name:

1. Build candidates: the configured name itself first, then the remaining alias
   peers, each with and without a `.service` suffix.
2. For each candidate, if a unit file exists under
   `/etc/systemd/system`, `/lib/systemd/system`, or
   `/usr/lib/systemd/system`, treat it as installed.
3. Otherwise run `systemctl show -p Id -p LoadState -- <candidate>`
   (timeout 2s, `check=False`). Parse stdout. `LoadState` other than
   `not-found` means installed; the resolved `Id` becomes the unit.
4. On FileNotFoundError/TimeoutExpired/OSError, return `unknown`.
5. Cache positive resolutions only. `not-found` is re-evaluated each cycle so
   newly installed units are picked up without a restart.

Versioned `php-fpm` units are not guessed. If an exact unit is needed, set it
explicitly (for example `SERVICES_OPTIONAL=php8.3-fpm`).

## Health evaluation

`HealthMonitor` receives the panel name (from server metadata) and builds
targets at construction:

- `targets = [(name, required), ...]`, deduped by configured name, required
  wins.
- After resolution, targets that resolve to the same unit are deduped again;
  the required entry wins. This prevents duplicate checks when a user lists
  alias variants (for example `mysql` and `mariadb`) explicitly.
- Profile targets are not filtered by `AUTO_DETECT_SERVICES`.
- Legacy `SERVICES` keeps the installed-only filter when
  `AUTO_DETECT_SERVICES=true`.

Per target per cycle:

1. Resolve the unit.
2. `not-found`:
   - required -> CRITICAL "Service is not installed/available".
   - optional -> skip.
3. `unknown`:
   - required -> WARNING "Service state could not be determined".
   - optional -> skip unless `ALERT_ON_MISSING_SERVICE=true`, then WARNING.
4. Resolved, run `systemctl is-active -- <unit>` (timeout 3s).
5. States:
   - `active` -> clear failure counter; if the service was previously in
     problem state and `RECOVERY_ALERTS=true`, emit INFO recovery.
   - `failed` -> CRITICAL immediately (required) or WARNING (optional).
   - `inactive`, `activating`, `deactivating`, other -> increment the
     consecutive-failure counter; alert only once
     `SERVICE_FAILURE_THRESHOLD` is reached. Required -> CRITICAL,
     optional -> WARNING.
   - empty output -> treat as `unknown`.

Incident details include `service`, `unit`, `state`, `required`,
`consecutive_failures`, and `error` (when present). Fingerprint remains
`service:<configured-name>` so cooldown and recovery state are stable across
alias resolution changes.

## State

Add `service_failures: {}` to `state.json` (coerced to a dict on load, like
the other sections). Methods on `StateStore`:

- `service_failure_count(key) -> int`
- `increment_service_failure(key) -> int` (persists)
- `clear_service_failure(key) -> None` (persists when the key existed)

Key format: `service:<configured-name>`. The existing `health_active` map still
records whether the service was in a problem state for recovery alerts.

## Evidence

`Incident.details["unit"]` carries the resolved unit. On service incidents the
evidence collector:

1. Validates the unit with `^[a-zA-Z0-9_@.:-]+$`.
2. Runs `journalctl -u <unit> -n <n> --no-pager`.
3. Appends `systemctl status --no-pager -l -- <unit>` (stdout + stderr).
4. Returns a bounded combined block with clear headers.

If the unit is absent (older path), fall back to the configured service name
with the existing validation.

## Installer and CLI

`install.sh`:

- Stops writing an active-only `SERVICES` snapshot.
- Writes `SERVICE_PROFILE=auto` (commented explanation) on new installs and
  preserves an existing value on update.
- Keeps `SERVICES=` present but commented as the legacy override.
- `--print-platform` is a pre-install hint, not a profile resolver: it reports
  the detected platform profile and states that the service profile is resolved
  at runtime. Use `--check-config` after install for the resolved
  required/optional lists.

`--check-config` after `Configuration OK` prints:

```
Service profile: cpanel (auto)
Required: cpanel, mysql, exim, dovecot
Optional: named, httpd, lsws, cphulkd, pure-ftpd, clamd, spamd, redis, php-fpm
```

This uses `EnvironmentDetector.detect()` when auto-detection is enabled.

## Backward compatibility

- A non-empty legacy `SERVICES` list still takes precedence and keeps
  `AUTO_DETECT_SERVICES` filtering, so upgrading an existing installation does
  not switch it to profiles. Remove or empty `SERVICES` to opt in.
- `SERVICE_PROFILE=none` and `SERVICES_REQUIRED`/`SERVICES_OPTIONAL` are ignored
  while legacy `SERVICES` is non-empty.
- Legacy monitoring severity semantics changed. With
  `AUTO_DETECT_SERVICES=false`, a missing legacy service is now `CRITICAL`
  (previously it was skipped when `ALERT_ON_MISSING_SERVICE=false`); `unknown`
  is now `WARNING`; and a non-active service alerts after
  `SERVICE_FAILURE_THRESHOLD` consecutive checks.
- Existing `state.json` files load with the new `service_failures` section
  defaulted to `{}`.
- Existing env files without `SERVICE_PROFILE` default to `auto`, but that only
  affects installations whose `SERVICES` list is empty.
- `ALERT_ON_MISSING_SERVICE` keeps its role for `unknown` and optional
  services.

## Testing

New and updated tests:

- `service_profiles`: auto per panel, standalone fallback, explicit profile,
  `none`, legacy `SERVICES` override, required/optional env overrides,
  dedupe, required-wins, invalid profile validation.
- alias resolution: `ssh`/`sshd`, `apache2`/`httpd`, `mysql`/`mariadb`/`mysqld`,
  `exim`/`exim4`, `redis`/`redis-server`, `powerdns`/`pdns`, unit-file hit vs
  `systemctl show`, not-found caching, systemctl unavailable -> unknown.
- health severity: required missing CRITICAL, optional missing skip, required
  inactive CRITICAL after threshold, `failed` immediate, optional inactive
  WARNING, unknown required WARNING, recovery INFO, threshold reset,
  persistence across reload.
- evidence: resolved unit used for journal and `systemctl status`, unsafe unit
  rejected, missing binary returns empty, fallback to configured name.
- config validation: profile allowlist, threshold bounds, duplicate in
  required+optional, unit-name validation.
- CLI: `--check-config` prints profile and resolved lists.
- `install.sh` syntax and `--print-platform` output.

Commands:

```bash
python -m ruff check .
python -m pytest -q --cov=server_agent --cov-report=term-missing
bash -n install.sh
```

## Risks

- `systemctl show` per unresolved service adds subprocess calls. Mitigation:
  positive cache; only required/optional targets are resolved; typical panels
  have a small target set.
- Panel profile accuracy varies by installation. Mitigation: profile is a
  default, env overrides win, and `--check-config` exposes the final lists.
- Required missing alerts can be noisy on deliberately minimal panels.
  Mitigation: users can move a service to `SERVICES_OPTIONAL` or set
  `SERVICE_PROFILE=none`.
- Alias groups are curated, not exhaustive. Mitigation: explicit unit names
  always work, and the alias map is easy to extend.

## Rollout

1. Implement config, profiles, resolver, health, state, evidence, CLI, installer,
   docs, and tests.
2. Run ruff, the full pytest suite with the coverage gate, and `bash -n`.
3. Update README with the Service Monitoring section, precedence, profile
   table, and troubleshooting.
4. Update `.env.example` with the new keys and legacy comments.
5. Commit in logical batches and push.
