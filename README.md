# unitslip

Find systemd service hardening that silently does not apply.

You add `ProtectSystem=strict`, `NoNewPrivileges=yes` and a `SystemCallFilter=` to a unit, the service starts, and everything looks hardened. But systemd is forgiving. A typo, a directive in the wrong section, a drop-in without a `[Service]` header, a file called `override.cnf`, an invalid boolean, an empty assignment in a later drop-in, or a full copy made with `systemctl edit --full` that drops the vendor's sandboxing all produce at most one journal line, and the service runs with less protection than the file claims.

`unitslip` replays systemd's own merge rules over your unit directories and tells you where the hardening you wrote differs from the hardening you get.

## What is novel

Existing tools look at one side of the problem. `systemd-analyze security` scores the *running* unit's effective settings but does not tell you *which line* failed to take effect or why, and it needs a live systemd. Unit-file linters check syntax per file. `unitslip` works offline on a directory tree (a host, a container image, a config repo) and models the merge:

- **priority directories** (`/etc` over `/run` over `/usr/lib`), so a full copy in `/etc` that replaces a vendor unit is compared against the vendor hardening it threw away
- **drop-in resolution**: `name.service.d/`, prefix drop-ins like `app-.service.d/`, top-level `service.d/`, sorted by filename across directories, with same-named drop-ins masked by higher-priority ones, and non-`.conf` files ignored
- **last assignment wins** for single values, and **empty assignment resets** for lists, so it can say "`SystemCallFilter=` in `99-debug.conf:2` wipes the 3 filters set in the vendor unit"
- **effective privilege per command**: `+` and `!` exec prefixes, `User=`, `DynamicUser=`, ambient capabilities

Every finding points at the file and line that caused it, plus a one-line fix.

## Checks

| ID | Severity | What it catches |
|----|----------|-----------------|
| US001 | high/medium | `[Service]` directive placed in `[Unit]` or `[Install]` (ignored) |
| US002 | high/medium/info | misspelled or wrong-case directive (`ProtectSytem=`, `nonewprivileges=`) |
| US003 | high/medium | invalid value (`NoNewPrivileges=ture`, `ProtectSystem=strcit`) is ignored |
| US004 | high/medium | later drop-in or line weakens a hardening value (`strict` to `full`, `yes` to `no` or empty) |
| US005 | high | empty assignment wipes earlier list restrictions (`SystemCallFilter=`, `CapabilityBoundingSet=`, `RestrictAddressFamilies=`, `IPAddressDeny=`, ...) |
| US006 | high/medium | `+` exec prefix bypasses all sandboxing; `!` prefix drops `User=` and runs as root |
| US007 | high/medium | `ReadWritePaths=` reopens `/`, root-escalation paths (`/etc/systemd`, `/etc/sudoers.d`, `/usr/bin`, ...) or home directories that `ProtectSystem`/`ProtectHome` covered |
| US008 | medium | secret-looking value inline in `Environment=` (readable by any user via `systemctl show`); value is never printed |
| US009 | high | command runs as root from `/tmp`, `/var/tmp`, `/dev/shm`, `/home`, or from a group/world-writable binary |
| US010 | high/medium | unit or drop-in file is world- or group-writable |
| US011 | high | `AmbientCapabilities=` hands a root-equivalent capability (or `~` inverse set) to a non-root user |
| US012 | high/medium | drop-in assignment outside any `[Section]` (forgot the `[Service]` header) |
| US013 | high/low | drop-in file that is never read because it does not end in `.conf` |
| US014 | high | higher-priority full copy of a unit drops vendor hardening |
| US015 | low | line with no `=` |
| US016 | high/medium | unknown section such as `[Serivce]`, which systemd skips whole |

`X-` keys and sections are treated as vendor extensions and skipped. Aliases (symlinks to another unit) are analyzed once under the real name. Masked units are skipped.

## Install

Python 3.8+, standard library only.

```bash
pip install git+https://github.com/rashedhasan090/unitslip
# or run from a checkout
git clone https://github.com/rashedhasan090/unitslip && cd unitslip
python3 -m unitslip --help
```

## Run

```bash
# scan the host's unit directories (default: /etc, /run, /usr/local/lib, /usr/lib, /lib)
unitslip

# a container image or rootfs: list directories highest priority first,
# and point --root at the tree so binary permission checks use it
unitslip img/etc/systemd/system img/usr/lib/systemd/system --root img

# one unit, JSON for CI, fail only on high
unitslip /etc/systemd/system/nginx.service --json --fail-on high
```

Exit code is 1 when any finding is at or above `--fail-on` (default `medium`), else 0. Use `--min-severity` to hide lower findings and `--fail-on never` for report-only.

## Demo

The `examples/` tree has a vendor `api.service` with good hardening and an `/etc` copy that looks similar but went wrong in a handful of quiet ways, plus a `backup.service` with a misspelled section.

```bash
python3 -m unitslip examples/etc/systemd/system examples/usr/lib/systemd/system --root examples
```

```text
unitslip 0.1.0: 2 unit(s), 10 finding(s) (9 high, 1 medium, 0 low, 0 info)

api.service
  effective hardening: none
  HIGH   US014 api.service  this higher-priority copy fully replaces examples/usr/lib/systemd/system/api.service and drops its NoNewPrivileges=yes, PrivateDevices=yes, ProtectHome=yes, ProtectSystem=strict
         fix: re-apply the vendor hardening in a drop-in instead of a full copy
  HIGH   US001 api.service:3  ProtectSystem= is a [Service] directive but sits in [Unit], so it is ignored
         fix: move it under [Service]
  HIGH   US006 api.service:7  ExecStartPre has the '+' prefix, so this command runs with full privileges and none of the unit's sandboxing (User=, Protect*, filters) applies to it
         fix: drop '+' or move the privileged step into a separate, audited unit
  HIGH   US003 api.service:9  NoNewPrivileges=ture is not a valid value and is ignored
         fix: valid values: yes or no
  HIGH   US004 10-debug.conf:2  ProtectHome=yes at api.service:10 is weakened to no by this drop-in
         fix: remove the override or justify it in a comment
  HIGH   US012 20-harden.conf:2  PrivateDevices= sits outside any [Section] and is ignored
         fix: add a [Service] header above it
  HIGH   US013 30-caps.cnf  drop-in is never read because its name does not end in .conf, so its hardening CapabilityBoundingSet never applies
         fix: rename it to 30-caps.conf
  MEDIUM US008 api.service:11  Environment= sets API_TOKEN (21 chars) inline; unit files are world-readable and any user can read it with systemctl show
         fix: use LoadCredential= or an EnvironmentFile= with mode 0600

backup.service
  effective hardening: PrivateTmp=yes
  HIGH   US009 backup.service:2  ExecStart runs /tmp/backup.sh as root from /tmp, where a non-root user can plant or swap the binary
         fix: install it under /usr/local/bin owned by root
  HIGH   US016 backup.service:5  ProtectSystem= is in unknown section [Serivce] (did you mean [Service]?), which systemd skips entirely
         fix: move it under [Service]
```

Note that `ReadWritePaths=/etc/systemd` in `api.service` is *not* flagged. Because `ProtectSystem=` ended up in `[Unit]`, there is no read-only protection for it to punch through. Fix US001 and US007 appears.

On a Debian 13 (trixie) machine with 122 unit files, the only findings are the four vendor services that deliberately open `/etc` for writing (hostnamed, localed, logind, timedated), reported as medium.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

42 tests cover the parser, every check, drop-in ordering and masking, prefix and top-level drop-ins, alias handling, and the CLI.

## Limits

- Static analysis of files, not the running manager. Settings from `systemctl set-property` (written to `/etc/systemd/system.control`) are included only if you pass that directory.
- Template instances (`foo@bar.service`) are analyzed through their template file.
- The built-in directive list covers the common [Service], exec, sandboxing, and resource-control keys. A directive that `unitslip` does not know shows up as `info` and is never treated as a typo unless it is very close to a known one.

## License

MIT
