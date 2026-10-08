"""Conservative per-target owner gate and global transfer gate."""
from dataclasses import dataclass
import errno
import fnmatch
import os
from pathlib import Path
import re
import time

from .safety import absolute


class Deferred(Exception):
    """Static reason codes only: never embed process arguments or source content."""


@dataclass(frozen=True)
class Process:
    comm: str
    exe: str
    cmdline: str
    fds: tuple = ()
    pid: int = -1
    uid: int = -1
    fd_check: str = "verified"


POLL_SECONDS = 0.100
PROC_RETRIES = 3
PROC_RETRY_SECONDS = 0.050
GONE = {errno.ENOENT, errno.ESRCH}


class _Gone(Exception):
    pass


class _Retry(Exception):
    pass


def _proc_bytes(path, limit):
    # /proc reports zero sizes; a bounded read is required instead of stat size.
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise Deferred("process-state-unknown")
    return value


def _proc_stat(path):
    value = _proc_bytes(path / "stat", 65536)
    fields = value[value.rfind(b")") + 2:].split()
    if len(fields) < 20 or not fields[19].isdigit():
        raise _Retry
    return fields[0], fields[19]  # state and starttime guard against PID reuse


def _visibility(proc_root):
    if proc_root != Path("/proc"):
        return  # injectable fixture tree, never a CLI/config option
    try:
        rows = _proc_bytes(proc_root / "self/mountinfo", 4 * 1024 * 1024).decode().splitlines()
        for row in rows:
            before, after = row.split(" - ", 1)
            fields, filesystem = before.split(), after.split()
            if fields[4] == "/proc" and filesystem[0] == "proc":
                options = fields[5].split(",") + filesystem[2].split(",")
                if any(option.startswith("hidepid=") and option not in {"hidepid=0", "hidepid=off"} for option in options):
                    raise Deferred("process-visibility-restricted")
                return
    except (OSError, UnicodeError, ValueError, IndexError):
        pass
    raise Deferred("process-state-unknown")


def _capabilities(path):
    """Read only the permitted/effective masks; missing or invalid data is unknown."""
    try:
        status = _proc_bytes(path, 65536)
    except (OSError, Deferred):
        return None
    masks = {}
    for line in status.splitlines():
        field, _, value = line.partition(b":")
        if field in {b"CapPrm", b"CapEff"}:
            value = value.strip()
            if not re.fullmatch(rb"[0-9a-fA-F]+", value) or field in masks:
                return None
            masks[field] = int(value, 16)
    return masks if len(masks) == 2 else None


def _extra_capabilities(path):
    theirs = _capabilities(path / "status")
    ours = _capabilities(Path("/proc/self/status"))
    return bool(theirs and ours and any(theirs[field] & ~ours[field]
                                       for field in (b"CapPrm", b"CapEff")))


def _process(path, optional_exe=False):
    before = path.stat()
    same_uid = before.st_uid == os.getuid()
    state, started = _proc_stat(path)
    if state in {b"Z", b"X"}:
        return None  # exited tasks cannot own a live database/descriptor
    values = []
    for name, limit in (("comm", 4096), ("cmdline", 1024 * 1024)):
        try:
            values.append(_proc_bytes(path / name, limit))
        except OSError as exc:
            if exc.errno in GONE:
                raise _Gone from None
            values.append(None)
    comm, cmdline = values
    # Same-UID identity fields are required after bounded retries. For another
    # UID, a readable comm OR cmdline still supplies an owner-matching identity.
    if (same_uid and any(value is None for value in values)) or all(value is None for value in values):
        raise _Retry
    if not (comm or b"").strip() and not cmdline:
        raise _Retry
    fd_check = "unverifiable" if not same_uid else "verified"
    if same_uid:
        try:
            fd_owner = (path / "fd").stat().st_uid
        except OSError as exc:
            if exc.errno in GONE:
                raise _Gone from None
            raise _Retry("process-descriptor-state-unknown") from None
        if fd_owner == 0 and os.getuid() != 0:
            # Linux changes proc fd ownership for non-dumpable or elevated-cap
            # same-UID processes. Their readable names still gate owner checks.
            fd_check = "unverifiable"
        elif fd_owner != os.getuid():
            raise _Retry("process-descriptor-state-unknown")
    try:
        exe = os.readlink(path / "exe")
    except OSError as exc:
        if exc.errno in GONE:
            # Kernel threads have no exe, and exit/exec can remove this link.
            # Keep readable names, including any owner match, rather than lose it.
            exe = ""
        elif same_uid and fd_check == "verified" and not optional_exe:
            raise _Retry from None
        else:
            exe = ""  # supplementary identity; comm/cmdline still participate
    fds = []
    if same_uid and fd_check == "verified":
        denied_readlink = False
        try:
            for fd in (path / "fd").iterdir():
                try:
                    fds.append(os.readlink(fd))
                except OSError as exc:
                    if exc.errno in {errno.EACCES, errno.EPERM}:
                        denied_readlink = True
                    elif exc.errno not in GONE:
                        raise _Retry("process-descriptor-state-unknown") from None
        except OSError as exc:
            if exc.errno in GONE:
                raise _Gone from None
            raise _Retry("process-descriptor-state-unknown") from None
        if denied_readlink:
            # Only the final bounded reread may classify a still-denied link.
            # Root-owned fd directories above already cover non-dumpable tasks.
            if not optional_exe or not _extra_capabilities(path):
                raise _Retry("process-descriptor-state-unknown")
            fd_check = "unverifiable"
    # A disappearing PID is closed. A reused PID or changed UID is read afresh.
    after = path.stat()
    final_state, final_started = _proc_stat(path)
    if final_state in {b"Z", b"X"}:
        return None
    if (before.st_ino, before.st_uid, started) != (after.st_ino, after.st_uid, final_started):
        raise _Retry
    return Process((comm or b"").decode("utf-8", "replace").strip(), exe,
                   (cmdline or b"").replace(b"\0", b" ").decode("utf-8", "replace"),
                   tuple(fds), int(path.name), before.st_uid, fd_check)


def processes(proc_root=Path("/proc")):
    """Read names across UIDs; inspect descriptors for same-UID processes only.

    Unreadable live identity/same-UID descriptors defer after three 50 ms rereads.
    Other-UID exe/fd ptrace restrictions are not a failure of readable names.
    """
    _visibility(proc_root)
    try:
        pids = [path for path in proc_root.iterdir() if path.name.isdecimal() and int(path.name) != os.getpid()]
    except OSError:
        raise Deferred("process-state-unknown") from None
    result = []
    for path in pids:
        for attempt in range(PROC_RETRIES + 1):
            try:
                process = _process(path, optional_exe=attempt == PROC_RETRIES)
                if process is not None:
                    result.append(process)
                break
            except _Gone:
                break
            except (OSError, _Retry) as exc:
                if isinstance(exc, OSError) and exc.errno in GONE:
                    break
                if attempt == PROC_RETRIES:
                    reason = "process-descriptor-state-unknown" if exc.args == ("process-descriptor-state-unknown",) else "process-state-unknown"
                    raise Deferred(reason) from None
                time.sleep(PROC_RETRY_SECONDS)
    return result


def _target_strings(target):
    pattern = target["path"]
    return pattern, tuple(pattern + suffix for suffix in ("-wal", "-shm", "-journal")), pattern.rstrip("/") + "/" if target["class"] == "folder" else None


def _overlaps_normalized(path, prepared):
    pattern, sidecars, folder_prefix = prepared
    if fnmatch.fnmatchcase(path, pattern):
        return True
    if any(fnmatch.fnmatchcase(path, sidecar) for sidecar in sidecars):
        return True
    if folder_prefix and path.startswith(folder_prefix):
        return True
    return False


def overlaps(path, target):
    """Lexical only: never resolve/stat watched paths as part of the guard."""
    return _overlaps_normalized(str(absolute(path.removesuffix(" (deleted)"))), _target_strings(target))


class Guard:
    def __init__(self, cfg, reader=None):
        self.cfg = cfg
        self.reader = reader or processes
        self._last_check = {}
        self._target_paths = {target["name"]: _target_strings(target) for target in cfg["targets"]}
        self._transfer_dirs = tuple(str(absolute(folder)).casefold() for folder in cfg["transfer_dirs"])
        self.open_file_check = "verified"

    def check(self, force=True, targets=None):
        # No stale heartbeat/attestation is ever accepted as current remote state.
        if any(machine != "local" for machine in self.cfg["machines"]):
            raise Deferred("remote-process-state-unknown")
        targets = self.cfg["targets"] if targets is None else targets
        scope = tuple(target["name"] for target in targets)
        started = time.monotonic()
        last = self._last_check.get(scope)
        if not force and last is not None and 0 <= started - last < POLL_SECONDS:
            return
        try:
            listing = self.reader()
        except Deferred:
            raise
        except Exception:
            raise Deferred("process-state-unknown") from None
        if any(process.fd_check == "unverifiable" for process in listing if process.pid != os.getpid()):
            self.open_file_check = "unverifiable"
        owner_names = {owner for target in targets for owner in target["owners"]}
        patterns = [pattern.casefold() for owner in owner_names for pattern in self.cfg["owners"][owner]]
        transfers = [v.casefold() for v in self.cfg["transfer_commands"]]
        for process in listing:
            # Exclude only this invocation, never its parent, siblings or workers.
            if process.pid == os.getpid():
                continue
            text = "\n".join((process.comm, process.exe, process.cmdline)).casefold()
            if any(pattern in text for pattern in patterns):
                raise Deferred("owning-app-running")
            # Transfer scope is deliberately conservative: any configured
            # transfer process stops the whole run, even if argv is ambiguous.
            if any(pattern in text for pattern in transfers):
                raise Deferred("transfer-running")
            if any(_overlaps_normalized(os.path.abspath(fd.removesuffix(" (deleted)")), self._target_paths[target["name"]])
                   for fd in process.fds if fd.startswith("/") for target in targets):
                raise Deferred("target-handle-open")
            if any(folder in text for folder in self._transfer_dirs):
                raise Deferred("transfer-directory-in-use")
        # Only after owners are proven absent may even lock metadata be checked.
        for path in self.cfg["transfer_locks"]:
            try:
                os.lstat(absolute(path))
            except FileNotFoundError:
                continue
            except OSError:
                raise Deferred("transfer-lock-state-unknown") from None
            raise Deferred("transfer-lock-present")
        # A slow /proc walk must not make the next checkpoint immediately due.
        self._last_check[scope] = time.monotonic()
