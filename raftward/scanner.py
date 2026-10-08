"""Bounded plain reads; SQLite sees only disposable private copies."""
from collections import Counter
from contextlib import contextmanager
import errno
import fcntl
import fnmatch
import hashlib
import math
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import tempfile
from urllib.parse import quote

from .guard import Deferred
from .safety import absolute, directory_fd, fingerprint, private_dir

MAGIC = b"SQLite format 3\0"
CHUNK = 64 * 1024


def signature(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode


def entropy(data):
    return -sum((n / len(data)) * math.log2(n / len(data)) for n in Counter(data).values()) if data else 0.0


class Scanner:
    def __init__(self, cfg, guard, key, runtime, max_bytes=None, quick=False):
        self.cfg, self.guard, self.key = cfg, guard, key
        self.runtime = absolute(runtime)
        self.max_bytes, self.quick = max_bytes, quick
        self.bytes = 0
        self.count = 0
        self.active_target = None
        self.skipped = []

    def checkpoint(self, force=False):
        targets = [self.active_target] if self.active_target is not None else None
        self.guard.check(force=force, targets=targets)

    @contextmanager
    def runtime_guard(self):
        """Clean abandoned private copies without racing another active run."""
        private_dir(self.runtime)
        fd = directory_fd(self.runtime)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Deferred("another-run-active") from None
            with os.scandir(fd) as entries:
                for entry in entries:
                    if not entry.name.startswith("run-"):
                        continue
                    info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                        raise Deferred("runtime-stale-copy-unsafe")
                    shutil.rmtree(self.runtime / entry.name)
            yield
        finally:
            os.close(fd)

    def _stat(self, path):
        self.checkpoint(force=True)
        parent = directory_fd(path.parent)
        try:
            self.checkpoint(force=True)
            result = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            self.checkpoint()
            if stat.S_ISLNK(result.st_mode) or result.st_uid != os.getuid():
                raise Deferred("unsafe-target-type-or-owner")
            return result
        finally:
            os.close(parent)

    def _names(self, path):
        self.checkpoint(force=True)
        fd = directory_fd(path)
        try:
            if os.fstat(fd).st_uid != os.getuid():
                raise Deferred("unsafe-target-type-or-owner")
            self.checkpoint()
            with os.scandir(fd) as entries:
                names = []
                for entry in entries:
                    self.checkpoint()
                    names.append(entry.name)
                    if len(names) > self.cfg["max_files"]:
                        raise Deferred("file-count-budget-exceeded")
            self.checkpoint()
            return sorted(names)
        finally:
            os.close(fd)

    def expand(self, pattern):
        """Expand globs without following any symlink. ** is intentionally unsupported."""
        parts = absolute(pattern).parts[1:]
        paths = [Path("/")]
        for component in parts:
            if component == "**":
                raise Deferred("recursive-glob-unsupported-use-folder")
            next_paths = []
            for parent in paths:
                self.checkpoint()
                if any(c in component for c in "*?["):
                    try:
                        names = self._names(parent)
                    except FileNotFoundError:
                        continue
                    next_paths.extend(parent / name for name in names if fnmatch.fnmatchcase(name, component))
                else:
                    next_paths.append(parent / component)
                if len(next_paths) > self.cfg["max_files"]:
                    raise Deferred("file-count-budget-exceeded")
            paths = next_paths
        return paths

    def files(self, path, folder):
        try:
            info = self._stat(path)
        except FileNotFoundError:
            return
        if stat.S_ISDIR(info.st_mode):
            if not folder:
                raise Deferred("file-target-is-directory")
            for name in self._names(path):
                yield from self.files(path / name, True)
            self.checkpoint()
            if signature(info) != signature(self._stat(path)):
                raise Deferred("source-changed-during-read")
        elif stat.S_ISREG(info.st_mode):
            self.count += 1
            if self.count > self.cfg["max_files"]:
                raise Deferred("file-count-budget-exceeded")
            yield path
        else:
            raise Deferred("unsafe-target-type-or-owner")

    def no_sidecars(self, parent, name):
        for suffix in ("-wal", "-shm", "-journal"):
            self.checkpoint(force=True)
            try:
                os.stat(name + suffix, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise Deferred("sqlite-sidecar-present")

    def sqlite_copy(self, copy):
        self.checkpoint(force=True)
        cancellation = []

        def progress():
            try:
                self.checkpoint()
            except (Deferred, KeyboardInterrupt) as exc:
                cancellation.append(exc)
                return 1
            return 0

        connection = None
        try:
            connection = sqlite3.connect("file:" + quote(str(copy), safe="/") + "?mode=ro&immutable=1", uri=True)
            connection.set_progress_handler(progress, 100)
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA temp_store=MEMORY")
            self.checkpoint(force=True)
            cursor = connection.execute("PRAGMA " + ("quick_check" if self.quick else "integrity_check"))
            good = True
            for row in cursor:
                self.checkpoint()
                if row != ("ok",):
                    good = False
            self.checkpoint()
            pages = connection.execute("PRAGMA page_count").fetchone()[0]
            self.checkpoint(force=True)
            return ("ok" if good else "not ok"), pages
        except sqlite3.Error as exc:
            if cancellation:
                raise cancellation[0]
            if (getattr(exc, "sqlite_errorcode", None) == getattr(sqlite3, "SQLITE_INTERRUPT", 9)
                    or str(exc).casefold() == "interrupted"):
                raise KeyboardInterrupt from None
            self.checkpoint(force=True)
            return "not ok", None
        finally:
            if connection is not None:
                connection.close()

    def read_file(self, path, target, expected_sqlite=False):
        self.checkpoint(force=True)
        parent = directory_fd(path.parent)
        fd, tempdir, output = None, None, None
        try:
            self.checkpoint(force=True)
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            try:
                fd = os.open(path.name, flags | getattr(os, "O_NOATIME", 0), dir_fd=parent)
            except OSError as exc:
                if exc.errno not in (errno.EPERM, errno.EACCES):
                    raise
                self.checkpoint(force=True)
                fd = os.open(path.name, flags, dir_fd=parent)
            self.checkpoint(force=True)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
                raise Deferred("unsafe-target-type-or-owner")
            if self.max_bytes is not None and self.bytes + before.st_size > self.max_bytes:
                raise Deferred("byte-budget-exceeded")
            digest, sample = hashlib.sha256(), bytearray()
            copied = 0
            is_db = expected_sqlite or target["sqlite"]
            first = True
            while True:
                block = os.read(fd, CHUNK)
                if first:
                    is_db = is_db or block.startswith(MAGIC)
                    if is_db:
                        self.no_sidecars(parent, path.name)
                    if is_db and block.startswith(MAGIC):
                        private_dir(self.runtime)
                        self.checkpoint(force=True)
                        tempdir = Path(tempfile.mkdtemp(prefix="run-", dir=self.runtime))
                        copy = tempdir / "snapshot.sqlite"
                        output = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    first = False
                if not block:
                    self.checkpoint()
                    break
                copied += len(block)
                self.bytes += len(block)
                if self.max_bytes is not None and self.bytes > self.max_bytes:
                    raise Deferred("byte-budget-exceeded")
                digest.update(block)
                sample.extend(block[:max(0, 4096 - len(sample))])
                if output is not None:
                    view = memoryview(block)
                    while view:
                        view = view[os.write(output, view):]
                self.checkpoint()
            self.checkpoint(force=True)
            after = os.fstat(fd)
            self.checkpoint(force=True)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            self.checkpoint()
            if signature(before) != signature(after) or signature(before) != signature(named) or copied != before.st_size:
                raise Deferred("source-changed-during-read")
            if is_db:
                self.no_sidecars(parent, path.name)
            if output is not None:
                os.close(output)
                output = None
                integrity, pages = self.sqlite_copy(copy)
                self.checkpoint(force=True)
                if signature(before) != signature(os.stat(path.name, dir_fd=parent, follow_symlinks=False)):
                    raise Deferred("source-changed-during-read")
                self.no_sidecars(parent, path.name)
            else:
                integrity, pages = "not checked", None
            self.checkpoint(force=True)
            return {"target": target.get("identity", target["name"]), "label": target["name"], "path": str(path), "class": target["class"],
                    "size": before.st_size, "mtime_ns": before.st_mtime_ns, "inode": before.st_ino,
                    "mode": stat.S_IMODE(before.st_mode), "sha256": digest.hexdigest(),
                    "sqlite": is_db, "sqlite_magic": bytes(sample[:16]) == MAGIC,
                    "integrity": integrity, "page_count": pages, "entropy": round(entropy(sample), 4)}
        finally:
            if output is not None:
                os.close(output)
            if fd is not None:
                os.close(fd)
            os.close(parent)
            if tempdir is not None:
                shutil.rmtree(tempdir)

    def scan(self, targets, baseline):
        entries, missing = {}, []
        try:
            with self.runtime_guard():
                for target in targets:
                    self.active_target = target
                    target_entries = {}
                    found = False
                    try:
                        self.checkpoint(force=True)
                        for root in self.expand(target["path"]):
                            try:
                                self._stat(root)
                            except FileNotFoundError:
                                continue
                            found = True
                            for path in self.files(root, target["class"] == "folder"):
                                identity = fingerprint(self.key, target["name"] + "\0" + str(path))
                                target_entries[identity] = self.read_file(path, target, baseline.get(identity, {}).get("sqlite", False))
                        self.checkpoint(force=True)
                    except Deferred as exc:
                        if str(exc) != "owning-app-running":
                            raise
                        self.skipped.append({"name": target["name"], "reason": "owning-app-running"})
                        continue
                    finally:
                        self.active_target = None
                    entries.update(target_entries)
                    if not found:
                        missing.append(target["name"])
            return entries, missing
        except Deferred:
            raise
        except (OSError, ValueError, RecursionError):
            raise Deferred("source-state-unknown") from None
