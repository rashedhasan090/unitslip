"""unitslip: find systemd service hardening that silently does not apply.

systemd is forgiving. A misspelled directive, a directive in the wrong
section, a drop-in without a [Service] header, a file named override.cnf,
an invalid boolean, or a later drop-in that resets a list all produce at
most a log line, and the service starts anyway with less sandboxing than
the unit file appears to promise. unitslip replays systemd's own merge
rules (priority directories, drop-in ordering, last-assignment-wins, empty
assignment resets) and reports every place where the hardening you wrote
is not the hardening you get.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import shlex
import stat
import sys
from dataclasses import dataclass, field

__version__ = "0.1.0"

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

BOOL_TRUE = {"1", "yes", "y", "true", "t", "on"}
BOOL_FALSE = {"0", "no", "n", "false", "f", "off"}


def parse_bool(v):
    v = v.strip().lower()
    if v in BOOL_TRUE:
        return True
    if v in BOOL_FALSE:
        return False
    return None


BOOL_HARDENING = [
    "NoNewPrivileges", "PrivateTmp", "PrivateDevices", "PrivateNetwork",
    "PrivateIPC", "PrivateMounts", "ProtectKernelTunables",
    "ProtectKernelModules", "ProtectKernelLogs", "ProtectClock",
    "RestrictRealtime", "RestrictSUIDSGID", "LockPersonality",
    "MemoryDenyWriteExecute", "RemoveIPC", "DynamicUser",
]

ENUM_HARDENING = {
    "ProtectSystem": {"no": 0, "yes": 1, "full": 2, "strict": 3},
    "ProtectHome": {"no": 0, "read-only": 1, "tmpfs": 2, "yes": 3},
    "ProtectProc": {"default": 0, "ptraceable": 1, "invisible": 2, "noaccess": 3},
    "ProtectControlGroups": {"no": 0, "yes": 1, "private": 1, "strict": 2},
    "ProtectHostname": {"no": 0, "yes": 1, "private": 1},
}

HARDENING = set(BOOL_HARDENING) | set(ENUM_HARDENING)

# Lists where an empty assignment silently throws away earlier restrictions.
LIST_RESTRICTIONS = {
    "SystemCallFilter", "SystemCallArchitectures", "CapabilityBoundingSet",
    "RestrictAddressFamilies", "IPAddressDeny", "InaccessiblePaths",
    "ReadOnlyPaths", "NoExecPaths", "RestrictFileSystems", "RestrictNamespaces",
}

EXEC_KEYS = {
    "ExecStart", "ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop",
    "ExecStopPost", "ExecCondition",
}

LIST_KEYS = LIST_RESTRICTIONS | EXEC_KEYS | {
    "ReadWritePaths", "Environment", "EnvironmentFile", "AmbientCapabilities",
    "SupplementaryGroups", "BindPaths", "BindReadOnlyPaths", "LoadCredential",
    "SetCredential", "ExecPaths", "IPAddressAllow", "DeviceAllow",
    "TemporaryFileSystem", "PassEnvironment", "UnsetEnvironment",
}

OTHER_SERVICE_KEYS = """
Type ExitType RemainAfterExit GuessMainPID PIDFile BusName Restart RestartSec
RestartSteps RestartMaxDelaySec TimeoutStartSec TimeoutStopSec TimeoutAbortSec
TimeoutSec RuntimeMaxSec RuntimeRandomizedExtraSec WatchdogSec
SuccessExitStatus RestartPreventExitStatus RestartForceExitStatus
RootDirectoryStartOnly NonBlocking NotifyAccess Sockets FileDescriptorStoreMax
FileDescriptorStorePreserve USBFunctionDescriptors USBFunctionStrings OOMPolicy
OpenFile ReloadSignal WorkingDirectory RootDirectory RootImage
RootImageOptions RootEphemeral RootHash RootHashSignature RootVerity
MountAPIVFS ProtectProc ProcSubset ExtensionDirectories ExtensionImages
User Group SupplementaryGroups SetLoginEnvironment PAMName
CapabilityBoundingSet AmbientCapabilities SecureBits KeyringMode
OOMScoreAdjust TimerSlackNSec Personality IgnoreSIGPIPE Nice CPUSchedulingPolicy
CPUSchedulingPriority CPUSchedulingResetOnFork CPUAffinity NUMAPolicy NUMAMask
IOSchedulingClass IOSchedulingPriority UMask CoredumpFilter LimitCPU
LimitFSIZE LimitDATA LimitSTACK LimitCORE LimitRSS LimitNOFILE LimitAS
LimitNPROC LimitMEMLOCK LimitLOCKS LimitSIGPENDING LimitMSGQUEUE LimitNICE
LimitRTPRIO LimitRTTIME RuntimeDirectory StateDirectory CacheDirectory
LogsDirectory ConfigurationDirectory RuntimeDirectoryMode StateDirectoryMode
CacheDirectoryMode LogsDirectoryMode ConfigurationDirectoryMode
RuntimeDirectoryPreserve ReadWritePaths ReadOnlyPaths InaccessiblePaths
ExecPaths NoExecPaths TemporaryFileSystem PrivateUsers PrivatePIDs
BindPaths BindReadOnlyPaths MountImages MountFlags
SystemCallFilter SystemCallErrorNumber SystemCallArchitectures SystemCallLog
RestrictAddressFamilies RestrictFileSystems RestrictNamespaces
RestrictNetworkInterfaces NetworkNamespacePath IPCNamespacePath
PrivateIPC Environment EnvironmentFile PassEnvironment UnsetEnvironment
StandardInput StandardOutput StandardError StandardInputText StandardInputData
LogLevelMax LogExtraFields LogRateLimitIntervalSec LogRateLimitBurst
LogFilterPatterns LogNamespace SyslogIdentifier SyslogFacility SyslogLevel
SyslogLevelPrefix TTYPath TTYReset TTYVHangup TTYVTDisallocate TTYRows
TTYColumns LoadCredential LoadCredentialEncrypted ImportCredential
SetCredential SetCredentialEncrypted UtmpIdentifier UtmpMode SELinuxContext
AppArmorProfile SmackProcessLabel KillMode KillSignal RestartKillSignal
SendSIGHUP SendSIGKILL FinalKillSignal WatchdogSignal CPUAccounting
CPUWeight StartupCPUWeight CPUQuota CPUQuotaPeriodSec AllowedCPUs
StartupAllowedCPUs MemoryAccounting MemoryMin MemoryLow MemoryHigh MemoryMax
MemorySwapMax MemoryZSwapMax AllowedMemoryNodes TasksAccounting TasksMax
IOAccounting IOWeight StartupIOWeight IODeviceWeight IOReadBandwidthMax
IOWriteBandwidthMax IOReadIOPSMax IOWriteIOPSMax IODeviceLatencyTargetSec
IPAccounting IPAddressAllow IPAddressDeny IPIngressFilterPath
IPEgressFilterPath BPFProgram SocketBindAllow SocketBindDeny DeviceAllow
DevicePolicy Slice Delegate DisableControllers ManagedOOMSwap
ManagedOOMMemoryPressure ManagedOOMMemoryPressureLimit ManagedOOMPreference
MemoryPressureWatch MemoryPressureThresholdSec CPUShares MemoryLimit
""".split()

SERVICE_KEYS = HARDENING | LIST_KEYS | set(OTHER_SERVICE_KEYS)

UNIT_KEYS = set("""
Description Documentation Wants Requires Requisite BindsTo PartOf Upholds
Conflicts Before After OnFailure OnSuccess PropagatesReloadTo ReloadPropagatedFrom
PropagatesStopTo StopPropagatedFrom JoinsNamespaceOf RequiresMountsFor
OnFailureJobMode IgnoreOnIsolate StopWhenUnneeded RefuseManualStart
RefuseManualStop AllowIsolate DefaultDependencies CollectMode FailureAction
SuccessAction FailureActionExitStatus SuccessActionExitStatus JobTimeoutSec
JobRunningTimeoutSec JobTimeoutAction JobTimeoutRebootArgument
StartLimitIntervalSec StartLimitBurst StartLimitAction RebootArgument
SourcePath ConditionPathExists AssertPathExists ConditionHost
""".split())

INSTALL_KEYS = {"Alias", "WantedBy", "RequiredBy", "UpheldBy", "Also", "DefaultInstance"}
KNOWN_SECTIONS = {"Unit", "Service", "Install"}

DANGEROUS_CAPS = {
    "CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_SYS_RAWIO",
    "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_SETUID", "CAP_SETGID",
    "CAP_CHOWN", "CAP_FOWNER", "CAP_BPF", "CAP_SYS_BOOT", "CAP_MKNOD",
    "CAP_SETFCAP",
}

# Paths whose write access is enough to become root on most systems.
ESCALATION_PATHS = [
    "/etc/systemd", "/etc/sudoers", "/etc/sudoers.d", "/etc/cron.d",
    "/etc/crontab", "/etc/ld.so.preload", "/etc/ld.so.conf.d", "/etc/profile.d",
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/pam.d", "/etc/ssh",
    "/etc/polkit-1", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local/bin",
    "/usr/local/sbin", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/root/.ssh",
]

WRITABLE_EXEC_DIRS = ["/tmp", "/var/tmp", "/dev/shm", "/home", "/run/user"]

SECRET_NAME = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api_?key|access_?key|private_?key|credential|auth)")


@dataclass
class Assign:
    section: object
    key: str
    value: object
    path: str
    line: int


@dataclass
class Finding:
    id: str
    severity: str
    unit: str
    path: str
    line: int
    message: str
    fix: str = ""

    def to_dict(self):
        return {"id": self.id, "severity": self.severity, "unit": self.unit,
                "path": self.path, "line": self.line, "message": self.message,
                "fix": self.fix}


@dataclass
class UnitReport:
    name: str
    main: str
    dropins: list = field(default_factory=list)
    effective: dict = field(default_factory=dict)
    masked: bool = False


def parse_unit_text(text, path):
    """Parse unit-file text into assignments, following systemd's syntax."""
    out = []
    section = None
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        lineno = i + 1
        i += 1
        s = raw.strip()
        if not s or s[0] in "#;":
            continue
        if s.startswith("[") and s.endswith("]"):
            section = s[1:-1].strip()
            continue
        while s.endswith("\\") and i < len(lines):
            nxt = lines[i].strip()
            i += 1
            if nxt.startswith(("#", ";")):
                continue
            s = s[:-1].rstrip() + " " + nxt
        if s.endswith("\\"):
            s = s[:-1].rstrip()
        if "=" not in s:
            out.append(Assign(section, s, None, path, lineno))
            continue
        k, v = s.split("=", 1)
        out.append(Assign(section, k.strip(), v.strip(), path, lineno))
    return out


def rank(key, value):
    """Strength of a hardening value (higher is stricter), or None if invalid."""
    if value == "":
        return 0
    if key in ENUM_HARDENING:
        lv = value.strip().lower()
        b = parse_bool(lv)
        if b is not None:
            lv = "yes" if b else "no"
        return ENUM_HARDENING[key].get(lv)
    if key in BOOL_HARDENING:
        b = parse_bool(value)
        return None if b is None else int(b)
    return None


def _read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _prefix_dropin_dirs(name):
    base, dot, suffix = name.rpartition(".")
    names = [name + ".d"]
    parts = base.split("-")
    for k in range(len(parts) - 1, 0, -1):
        names.append("-".join(parts[:k]) + "-." + suffix + ".d")
    names.append(suffix + ".d")
    return names


def discover(dirs):
    """Map unit name -> list of main files in priority order (first wins)."""
    units = {}
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for entry in sorted(os.listdir(d)):
            p = os.path.join(d, entry)
            if entry.endswith(".service") and (os.path.isfile(p) or os.path.islink(p)):
                units.setdefault(entry, []).append(p)
    return units


def collect_dropins(name, dirs):
    chosen = {}
    ignored = []
    for d in dirs:
        for dd in _prefix_dropin_dirs(name):
            full = os.path.join(d, dd)
            if not os.path.isdir(full):
                continue
            for entry in sorted(os.listdir(full)):
                p = os.path.join(full, entry)
                if not os.path.isfile(p):
                    continue
                if entry.endswith(".conf"):
                    chosen.setdefault(entry, p)
                else:
                    ignored.append(p)
    return [chosen[k] for k in sorted(chosen)], ignored


def is_masked(path):
    try:
        if os.path.islink(path) and os.path.realpath(path) == "/dev/null":
            return True
        return os.path.getsize(path) == 0
    except OSError:
        return False


def _under(path, base):
    if base == "/":
        return True
    return path == base or path.startswith(base.rstrip("/") + "/")


def _norm(p):
    p = re.sub(r"/+", "/", p)
    return p if p == "/" else p.rstrip("/")


def _covered(path, ps, ph):
    if ps >= 3 and not any(_under(path, b) for b in ("/dev", "/proc", "/sys")):
        return True
    usr = ("/usr", "/boot", "/efi", "/bin", "/sbin", "/lib", "/lib64")
    if ps >= 1 and any(_under(path, b) for b in usr):
        return True
    if ps >= 2 and _under(path, "/etc"):
        return True
    if ph >= 1 and any(_under(path, b) for b in ("/home", "/root", "/run/user")):
        return True
    return False


def _split_words(value):
    try:
        return shlex.split(value)
    except ValueError:
        return value.split()


def _hardening_ranks(assigns):
    ranks = {}
    for a in assigns:
        if a.section == "Service" and a.key in HARDENING and a.value is not None:
            r = rank(a.key, a.value)
            if r is not None:
                ranks[a.key] = (r, a)
    return ranks


def analyze_unit(name, mains, dirs, fs_root="/"):
    findings = []
    main = mains[0]
    report = UnitReport(name=name, main=main)

    def add(fid, sev, a_or_path, msg, fix="", line=0):
        if isinstance(a_or_path, Assign):
            findings.append(Finding(fid, sev, name, a_or_path.path, a_or_path.line, msg, fix))
        else:
            findings.append(Finding(fid, sev, name, a_or_path, line, msg, fix))

    if is_masked(main):
        report.masked = True
        return report, findings

    dropins, ignored = collect_dropins(name, dirs)
    report.dropins = dropins
    files = [main] + dropins

    for p in files:
        try:
            mode = os.stat(p).st_mode
        except OSError:
            continue
        if mode & stat.S_IWOTH:
            add("US010", "high", p, "unit file is world-writable, so any local user can rewrite this service",
                "chmod 0644 and chown root:root")
        elif mode & stat.S_IWGRP:
            add("US010", "medium", p, "unit file is group-writable",
                "chmod 0644 unless the group is trusted with root")

    for p in ignored:
        try:
            body = parse_unit_text(_read(p), p)
        except OSError:
            continue
        keys = [a.key for a in body if a.value is not None]
        if not keys:
            continue
        hard = sorted(set(k for k in keys if k in HARDENING or k in LIST_RESTRICTIONS))
        sev = "high" if hard else "low"
        what = ("hardening " + ", ".join(hard)) if hard else (str(len(keys)) + " assignment(s)")
        add("US013", sev, p, "drop-in is never read because its name does not end in .conf, so its "
            + what + " never applies", "rename it to " + os.path.basename(p).split(".")[0] + ".conf")

    assigns = []
    for p in files:
        try:
            assigns.extend(parse_unit_text(_read(p), p))
        except OSError:
            continue

    eff = {}
    lists = {}
    known_lower = {k.lower(): k for k in SERVICE_KEYS}

    for a in assigns:
        if a.value is None:
            add("US015", "low", a, "line has no '=' and is ignored: " + a.key[:60])
            continue
        if a.section is None:
            sev = "high" if a.key in HARDENING or a.key in LIST_RESTRICTIONS else "medium"
            add("US012", sev, a, a.key + "= sits outside any [Section] and is ignored",
                "add a [Service] header above it")
            continue
        if a.section not in KNOWN_SECTIONS:
            if a.section.startswith("X-"):
                continue
            guess = difflib.get_close_matches(a.section, sorted(KNOWN_SECTIONS), n=1, cutoff=0.6)
            sev = "high" if a.key in HARDENING or a.key in LIST_RESTRICTIONS else "medium"
            hint = (" (did you mean [" + guess[0] + "]?)") if guess else ""
            add("US016", sev, a, a.key + "= is in unknown section [" + a.section + "]" + hint
                + ", which systemd skips entirely", "move it under [Service]")
            continue
        if a.section in ("Unit", "Install"):
            if a.key in SERVICE_KEYS and a.key not in UNIT_KEYS and a.key not in INSTALL_KEYS:
                sev = "high" if a.key in HARDENING or a.key in LIST_RESTRICTIONS else "medium"
                add("US001", sev, a, a.key + "= is a [Service] directive but sits in [" + a.section
                    + "], so it is ignored", "move it under [Service]")
            continue
        # [Service]
        key = a.key
        if key not in SERVICE_KEYS:
            if key.startswith("X-"):
                continue
            real = known_lower.get(key.lower())
            if real is None:
                m = difflib.get_close_matches(key, sorted(SERVICE_KEYS), n=1, cutoff=0.85)
                real = m[0] if m else None
            if real:
                sev = "high" if real in HARDENING or real in LIST_RESTRICTIONS else "medium"
                add("US002", sev, a, "unknown directive " + key + "= is ignored (did you mean "
                    + real + "=?)", "rename it to " + real + "=")
            else:
                add("US002", "info", a, "unknown directive " + key + "= (ignored by systemd versions that do not know it)")
            continue
        if key in LIST_KEYS:
            prev = lists.get(key, [])
            if a.value == "":
                if prev and key in LIST_RESTRICTIONS:
                    first = prev[0]
                    where = "a drop-in" if a.path != first.path else "a later line"
                    add("US005", "high", a, "empty " + key + "= in " + where + " wipes "
                        + str(len(prev)) + " earlier restriction(s), first at "
                        + os.path.basename(first.path) + ":" + str(first.line),
                        "restate the restriction after the reset, or drop the empty assignment")
                lists[key] = []
            else:
                lists[key] = prev + [a]
            continue
        if key in HARDENING:
            r = rank(key, a.value)
            old = eff.get(key)
            if r is None:
                sev = "high" if old is None else "medium"
                tail = "" if old is None else (", so the earlier " + key + "=" + old.value + " stays")
                add("US003", sev, a, key + "=" + a.value + " is not a valid value and is ignored" + tail,
                    "valid values: " + (", ".join(ENUM_HARDENING[key]) if key in ENUM_HARDENING else "yes or no"))
                continue
            if old is not None:
                ro = rank(key, old.value)
                if ro is not None and r < ro:
                    same = old.path == a.path
                    shown = a.value if a.value != "" else "(empty, resets to default)"
                    add("US004", "medium" if same else "high", a,
                        key + "=" + old.value + " at " + os.path.basename(old.path) + ":" + str(old.line)
                        + " is weakened to " + shown + (" later in the same file" if same else " by this drop-in"),
                        "remove the override or justify it in a comment")
            eff[key] = a
            continue
        eff[key] = a

    # effective hardening summary
    ranks = {}
    for k, a in eff.items():
        if k in HARDENING:
            r = rank(k, a.value)
            if r:
                ranks[k] = a.value
                report.effective[k] = a.value
    for k, lst in lists.items():
        if k in LIST_RESTRICTIONS and lst:
            report.effective[k] = " ".join(x.value for x in lst)

    user = eff["User"].value if "User" in eff else ""
    dyn = "DynamicUser" in ranks
    runs_root = (user in ("", "root", "0")) and not dyn
    sandboxed = bool(ranks) or not runs_root or any(lists.get(k) for k in LIST_RESTRICTIONS)

    for k in sorted(EXEC_KEYS):
        for a in lists.get(k, []):
            m = re.match(r"^([@\-:+!|]*)(.*)$", a.value)
            prefix, rest = m.group(1), m.group(2).strip()
            cmd_root = runs_root
            if "+" in prefix:
                cmd_root = True
                if sandboxed:
                    add("US006", "high", a, k + " has the '+' prefix, so this command runs with full privileges "
                        "and none of the unit's sandboxing (User=, Protect*, filters) applies to it",
                        "drop '+' or move the privileged step into a separate, audited unit")
            elif "!" in prefix and not runs_root:
                cmd_root = True
                add("US006", "medium", a, k + " has the '!' prefix, so User=/Group=/DynamicUser= are not applied "
                    "and this command runs as root", "drop '!' unless the command must start as root")
            words = _split_words(rest)
            argv0 = words[0] if words else ""
            if not cmd_root or not argv0.startswith("/"):
                continue
            hit = next((d for d in WRITABLE_EXEC_DIRS if _under(argv0, d)), None)
            if hit:
                add("US009", "high", a, k + " runs " + argv0 + " as root from " + hit
                    + ", where a non-root user can plant or swap the binary",
                    "install it under /usr/local/bin owned by root")
                continue
            real = os.path.join(fs_root, argv0.lstrip("/"))
            try:
                st = os.stat(real)
                pst = os.stat(os.path.dirname(real))
            except OSError:
                continue
            if st.st_mode & (stat.S_IWOTH | stat.S_IWGRP):
                add("US009", "high", a, k + " runs " + argv0 + " as root but the binary is group/world-writable",
                    "chmod go-w " + argv0)
            elif pst.st_mode & stat.S_IWOTH and not pst.st_mode & stat.S_ISVTX:
                add("US009", "high", a, k + " runs " + argv0 + " as root from a world-writable directory",
                    "move the binary to a root-owned directory")

    ps = rank("ProtectSystem", ranks.get("ProtectSystem", "no")) or 0
    ph = rank("ProtectHome", ranks.get("ProtectHome", "no")) or 0
    for a in lists.get("ReadWritePaths", []):
        for tok in _split_words(a.value):
            p = _norm(tok.lstrip("-+"))
            if not p.startswith("/") or not _covered(p, ps, ph):
                continue
            if p == "/":
                add("US007", "high", a, "ReadWritePaths=/ reopens the whole filesystem and cancels ProtectSystem="
                    + ranks.get("ProtectSystem", "no"), "list only the directories the service writes")
                continue
            esc = [e for e in ESCALATION_PATHS if _under(e, p)]
            if esc:
                add("US007", "medium", a, "ReadWritePaths=" + p + " punches a hole in ProtectSystem/ProtectHome "
                    "that exposes " + ", ".join(esc[:3]) + (" ..." if len(esc) > 3 else "")
                    + " (write there is enough to become root)", "narrow it to the service's own state dir")
            elif p in ("/home", "/root") or re.fullmatch(r"/home/[^/]+", p) or "/.ssh" in p:
                add("US007", "medium", a, "ReadWritePaths=" + p + " makes a home directory writable despite ProtectHome/ProtectSystem, "
                    "including ~/.ssh/authorized_keys", "use StateDirectory= instead")

    for a in lists.get("Environment", []):
        for tok in _split_words(a.value):
            if "=" not in tok:
                continue
            n, v = tok.split("=", 1)
            if SECRET_NAME.search(n) and v and not v.startswith(("$", "%")):
                add("US008", "medium", a, "Environment= sets " + n + " (" + str(len(v)) + " chars) inline; "
                    "unit files are world-readable and any user can read it with systemctl show",
                    "use LoadCredential= or an EnvironmentFile= with mode 0600")

    caps = []
    for a in lists.get("AmbientCapabilities", []):
        for tok in a.value.split():
            caps.append((tok, a))
    if caps and not runs_root:
        for tok, a in caps:
            if tok.startswith("~"):
                add("US011", "high", a, "AmbientCapabilities=" + tok + " grants every capability except the listed ones "
                    "to a non-root user, which is root-equivalent", "list the specific capability needed instead")
            elif tok.upper() in DANGEROUS_CAPS:
                add("US011", "high", a, "AmbientCapabilities grants " + tok.upper() + " to non-root User="
                    + (user or "(DynamicUser)") + ", which is root-equivalent in practice",
                    "drop it or replace it with a narrower capability")

    for loser in mains[1:]:
        try:
            lr = _hardening_ranks(parse_unit_text(_read(loser), loser))
        except OSError:
            continue
        lost = []
        for k, (r, la) in sorted(lr.items()):
            cur = rank(k, ranks[k]) if k in ranks else 0
            if r > cur:
                lost.append(k + "=" + la.value)
        if lost:
            add("US014", "high", main, "this higher-priority copy fully replaces " + loser + " and drops its "
                + ", ".join(lost), "re-apply the vendor hardening in a drop-in instead of a full copy")

    return report, findings


def scan(paths, fs_root="/", only=None):
    dirs = []
    wanted = set(only or [])
    for p in paths:
        if os.path.isfile(p) or (os.path.islink(p) and p.endswith(".service")):
            dirs.append(os.path.dirname(os.path.abspath(p)) or ".")
            wanted.add(os.path.basename(p))
        else:
            dirs.append(p)
    seen = []
    for d in dirs:
        if d not in seen:
            seen.append(d)
    units = discover(seen)
    reports, findings = [], []
    for name in sorted(units):
        if wanted and name not in wanted:
            continue
        main0 = units[name][0]
        if os.path.islink(main0):
            target = os.path.realpath(main0)
            if target.endswith(".service") and os.path.basename(target) != name and os.path.exists(target):
                continue  # alias of another unit; analyzed under its real name
        rep, f = analyze_unit(name, units[name], seen, fs_root)
        reports.append(rep)
        findings.extend(f)
    findings.sort(key=lambda f: (f.unit, -SEV_ORDER[f.severity], f.path, f.line))
    return reports, findings


def render_text(reports, findings, min_sev="info"):
    out = []
    shown = [f for f in findings if SEV_ORDER[f.severity] >= SEV_ORDER[min_sev]]
    counts = {s: sum(1 for f in shown if f.severity == s) for s in ("high", "medium", "low", "info")}
    out.append("unitslip %s: %d unit(s), %d finding(s) (%d high, %d medium, %d low, %d info)" % (
        __version__, len(reports), len(shown), counts["high"], counts["medium"], counts["low"], counts["info"]))
    for rep in reports:
        fs = [f for f in shown if f.unit == rep.name]
        if rep.masked or not fs:
            continue
        out.append("\n" + rep.name)
        eff = ", ".join(k + "=" + v for k, v in sorted(rep.effective.items()) if k in HARDENING)
        out.append("  effective hardening: " + (eff or "none"))
        for f in fs:
            loc = os.path.basename(f.path) + (":" + str(f.line) if f.line else "")
            out.append("  %-6s %s %s  %s" % (f.severity.upper(), f.id, loc, f.message))
            if f.fix:
                out.append("         fix: " + f.fix)
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="unitslip", description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="*", default=["/etc/systemd/system", "/run/systemd/system",
                                                 "/usr/local/lib/systemd/system", "/usr/lib/systemd/system",
                                                 "/lib/systemd/system"],
                    help="unit directories in priority order (highest first) or .service files")
    ap.add_argument("--unit", action="append", help="only report this unit (repeatable)")
    ap.add_argument("--root", default="/", help="filesystem root for binary permission checks (for images)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--min-severity", default="low", choices=list(SEV_ORDER), help="hide findings below this")
    ap.add_argument("--fail-on", default="medium", choices=list(SEV_ORDER) + ["never"],
                    help="exit 1 if any finding is at or above this severity")
    ap.add_argument("--version", action="version", version="unitslip " + __version__)
    args = ap.parse_args(argv)
    reports, findings = scan(args.paths, args.root, args.unit)
    shown = [f for f in findings if SEV_ORDER[f.severity] >= SEV_ORDER[args.min_severity]]
    if args.json:
        print(json.dumps({"version": __version__,
                          "units": [{"name": r.name, "main": r.main, "dropins": r.dropins,
                                     "masked": r.masked, "effective": r.effective} for r in reports],
                          "findings": [f.to_dict() for f in shown]}, indent=2))
    else:
        print(render_text(reports, findings, args.min_severity))
    if args.fail_on != "never" and any(SEV_ORDER[f.severity] >= SEV_ORDER[args.fail_on] for f in findings):
        return 1
    return 0
