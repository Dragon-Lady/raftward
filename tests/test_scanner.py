import hashlib
import os
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import sys
import time

import pytest

from raftward.guard import Deferred, Guard, Process
from raftward.scanner import Scanner


def scanner(config, monkeypatch, max_bytes=None):
    return Scanner(config, Guard(config), b"k" * 32, Path(os.environ["XDG_RUNTIME_DIR"]) / "raftward", max_bytes)


def snapshot(path):
    info = path.stat()
    return (hashlib.sha256(path.read_bytes()).hexdigest(), info.st_size, info.st_mtime_ns,
            info.st_ino, stat.S_IMODE(info.st_mode), sorted(p.name for p in path.parent.iterdir()))


def test_read_only_private_copy_and_cleanup(config, database, monkeypatch):
    before = snapshot(database)
    original_connect, original_open = sqlite3.connect, os.open
    opened, connected = [], []
    def connect(path, *args, **kw):
        connected.append(str(path))
        assert str(database) not in str(path)
        assert "mode=ro&immutable=1" in str(path)
        return original_connect(path, *args, **kw)
    def opened_file(path, flags, *args, **kw):
        if str(path) in (str(database), database.name):
            opened.append(flags)
        return original_open(path, flags, *args, **kw)
    monkeypatch.setattr(sqlite3, "connect", connect)
    monkeypatch.setattr(os, "open", opened_file)
    scan = scanner(config, monkeypatch)
    rows, missing = scan.scan(config["targets"], {})
    assert not missing
    row = next(iter(rows.values()))
    assert row["integrity"] == "ok" and row["page_count"] > 0
    assert connected and opened
    assert all(flags & os.O_ACCMODE == os.O_RDONLY for flags in opened)
    assert snapshot(database) == before
    assert list(scan.runtime.iterdir()) == []


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_sidecars_fail_closed_without_sqlite_open(config, database, monkeypatch, suffix):
    sidecar = Path(str(database) + suffix)
    sidecar.write_bytes(b"fixture-sidecar")
    before = snapshot(database)
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **k: pytest.fail("sidecar cannot be ignored"))
    scan = scanner(config, monkeypatch)
    with pytest.raises(Deferred, match="sqlite-sidecar-present"):
        scan.scan(config["targets"], {})
    assert snapshot(database) == before
    assert scan.runtime.exists() and not list(scan.runtime.iterdir())


def test_actual_wal_fixture_deferred_unchanged(config, database, monkeypatch):
    writer = sqlite3.connect(database)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("INSERT INTO items(value) VALUES ('uncheckpointed')")
    writer.commit()
    files = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in database.parent.iterdir()}
    with pytest.raises(Deferred, match="sqlite-sidecar-present"):
        scanner(config, monkeypatch).scan(config["targets"], {})
    assert {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in database.parent.iterdir()} == files
    writer.close()


def test_owner_appears_after_read_stops_before_next_read(config, database, monkeypatch):
    real_read = os.read
    active, calls = [], []
    def reader():
        return [Process("notebook-worker", "", "")] if active else []
    scan = Scanner(config, Guard(config, reader), b"k" * 32, Path(os.environ["XDG_RUNTIME_DIR"]) / "raftward")
    def read(fd, count):
        if os.readlink(f"/proc/self/fd/{fd}") == str(database):
            assert not active, "read continued after owner became observable"
            block = real_read(fd, count)
            active.append(True)
            calls.append(True)
            return block
        return real_read(fd, count)
    monkeypatch.setattr(os, "read", read)
    entries, missing = scan.scan(config["targets"], {})
    assert not entries and not missing
    assert scan.skipped == [{"name": "notes", "reason": "owning-app-running"}]
    assert calls == [True]
    assert not scan.runtime.exists() or not list(scan.runtime.iterdir())


def test_source_changes_mid_copy_deferred_and_cleaned(config, database, monkeypatch):
    real_read = os.read
    changed = []
    def read(fd, count):
        block = real_read(fd, count)
        if os.readlink(f"/proc/self/fd/{fd}") == str(database) and block and not changed:
            changed.append(True)
            with database.open("ab") as output:
                output.write(b"changed")
        return block
    monkeypatch.setattr(os, "read", read)
    scan = scanner(config, monkeypatch)
    with pytest.raises(Deferred, match="source-changed-during-read"):
        scan.scan(config["targets"], {})
    assert not list(scan.runtime.iterdir())


def test_exception_cleanup(config, database, monkeypatch):
    scan = scanner(config, monkeypatch)
    def explode(copy):
        assert copy.exists()
        assert stat.S_IMODE(copy.stat().st_mode) == 0o600
        assert stat.S_IMODE(copy.parent.stat().st_mode) == 0o700
        raise OSError("private-error")
    monkeypatch.setattr(scan, "sqlite_copy", explode)
    with pytest.raises(Deferred, match="source-state-unknown"):
        scan.scan(config["targets"], {})
    assert not list(scan.runtime.iterdir())


def test_owner_during_sqlite_progress_cancels_copy(config, database, monkeypatch):
    scan = scanner(config, monkeypatch)
    original = sqlite3.connect
    active = []
    clock = [1.0]
    monkeypatch.setattr("raftward.guard.time.monotonic", lambda: clock[0])
    class Wrapped:
        def __init__(self, connection):
            self.connection = connection
        def set_progress_handler(self, handler, n):
            def start():
                active.append(True)
                clock[0] += 0.101
                return handler()
            self.connection.set_progress_handler(start, n)
        def __getattr__(self, name):
            return getattr(self.connection, name)
    scan.guard.reader = lambda: [Process("notebook-worker", "", "")] if active else []
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **kw: Wrapped(original(*a, **kw)))
    entries, missing = scan.scan(config["targets"], {})
    assert not entries and not missing
    assert scan.skipped == [{"name": "notes", "reason": "owning-app-running"}]
    assert active and not list(scan.runtime.iterdir())


def test_budget_deferred(config, monkeypatch):
    with pytest.raises(Deferred, match="byte-budget-exceeded"):
        scanner(config, monkeypatch, 10).scan(config["targets"], {})


def test_symlink_never_followed(config, database, monkeypatch):
    link = database.parent / "link.sqlite"
    link.symlink_to(database)
    config["targets"][0]["path"] = str(link)
    with pytest.raises(Deferred, match="unsafe-target"):
        scanner(config, monkeypatch).scan(config["targets"], {})


def test_long_read_checks_owner_within_100ms_poll_interval(config, database, monkeypatch):
    from raftward import guard as guard_module
    target = database.parent / "large-fixture.bin"
    target.write_bytes(b"a" * (2 * 1024 * 1024))
    config["targets"] = [dict(config["targets"][0], path=str(target), sqlite=False, **{"class": "frozen"})]
    clock, active, reads = [1.0], [], []
    monkeypatch.setattr(guard_module.time, "monotonic", lambda: clock[0])
    gate = Guard(config, lambda: [Process("notebook-worker", "", "")] if active else [])
    scan = Scanner(config, gate, b"k" * 32, Path(os.environ["XDG_RUNTIME_DIR"]) / "raftward")
    original = os.read
    def read(fd, size):
        block = original(fd, size)
        if os.readlink(f"/proc/self/fd/{fd}") == str(target):
            assert len(reads) < 3
            reads.append(True)
            clock[0] += 0.040
            active.append(True)
        return block
    monkeypatch.setattr(os, "read", read)
    entries, missing = scan.scan(config["targets"], {})
    assert not entries and not missing
    assert scan.skipped == [{"name": "notes", "reason": "owning-app-running"}]
    assert len(reads) == 3  # next eligible 100 ms poll, no fourth read


def test_stale_private_copy_is_swept_before_scan(config, database, monkeypatch):
    runtime = Path(os.environ["XDG_RUNTIME_DIR"]) / "raftward"
    runtime.mkdir(mode=0o700)
    stale = runtime / "run-abandoned"
    stale.mkdir(mode=0o700)
    (stale / "snapshot.sqlite").write_bytes(b"private fixture")
    rows, missing = scanner(config, monkeypatch).scan(config["targets"], {})
    assert not missing and len(rows) == 1
    assert not list(runtime.iterdir())


@pytest.mark.parametrize("error_code_available", [True, False])
def test_sqlite_interrupt_without_callback_exception_is_cancellation(config, database, monkeypatch,
                                                                     error_code_available):
    class InterruptedConnection:
        def set_progress_handler(self, _callback, _steps):
            pass

        def execute(self, sql):
            if sql.startswith("PRAGMA integrity_check"):
                exc = sqlite3.OperationalError("interrupted")
                if error_code_available:
                    exc.sqlite_errorcode = getattr(sqlite3, "SQLITE_INTERRUPT", 9)
                raise exc
            return None

        def close(self):
            pass

    monkeypatch.setattr(sqlite3, "connect", lambda *args, **kwargs: InterruptedConnection())
    scan = Scanner(config, Guard(config, lambda: []), b"k" * 32,
                   Path(os.environ["XDG_RUNTIME_DIR"]) / "raftward")
    with pytest.raises(KeyboardInterrupt):
        scan.sqlite_copy(database)


def test_50mb_sqlite_finishes_with_150ms_process_reader(config, database):
    large = database.parent / "large.sqlite"
    with sqlite3.connect(large) as connection:
        connection.execute("CREATE TABLE payload (value BLOB)")
        connection.execute("INSERT INTO payload VALUES (zeroblob(?))", (50 * 1024 * 1024,))
    assert large.stat().st_size >= 50 * 1024 * 1024
    config["targets"][0]["path"] = str(large)
    calls = []
    def slow_reader():
        calls.append(True)
        time.sleep(0.150)
        return []
    scan = Scanner(config, Guard(config, slow_reader), b"k" * 32,
                   Path(os.environ["XDG_RUNTIME_DIR"]) / "raftward")
    started = time.monotonic()
    rows, missing = scan.scan(config["targets"], {})
    elapsed = time.monotonic() - started
    assert not missing and len(rows) == 1 and next(iter(rows.values()))["integrity"] == "ok"
    assert elapsed < 40, (elapsed, len(calls))
    assert not list(scan.runtime.iterdir())


@pytest.mark.parametrize("interrupt", [signal.SIGTERM, signal.SIGINT])
def test_signal_removes_active_private_copy(config, database, interrupt):
    large = database.parent / "interrupt.sqlite"
    with sqlite3.connect(large) as connection:
        connection.execute("CREATE TABLE payload (value BLOB)")
        connection.execute("INSERT INTO payload VALUES (zeroblob(?))", (16 * 1024 * 1024,))
    runtime = Path(os.environ["XDG_RUNTIME_DIR"]) / "raftward"
    script = """
import os, sys, time
from pathlib import Path
from raftward.cli import _Interrupted, _interrupt_cleanup
from raftward.config import validate
from raftward.guard import Guard
from raftward.scanner import Scanner
import raftward.scanner as module
source = Path(sys.argv[1])
cfg = validate({'owners': {'fixture': ['absent-raftward-owner']},
                'targets': [{'name': 'fixture', 'path': str(source), 'class': 'live', 'owners': ['fixture']}]})
original_write = os.write
def slow_write(fd, data):
    time.sleep(0.01)
    return original_write(fd, data)
module.os.write = slow_write
try:
    with _interrupt_cleanup():
        Scanner(cfg, Guard(cfg, lambda: []), b'k' * 32, Path(os.environ['XDG_RUNTIME_DIR']) / 'raftward').scan(cfg['targets'], {})
except _Interrupted as exc:
    sys.exit(128 + exc.signum)
"""
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    child = subprocess.Popen([sys.executable, "-c", script, str(large)], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and child.poll() is None:
            if list(runtime.glob("run-*/snapshot.sqlite")):
                break
            time.sleep(0.01)
        assert list(runtime.glob("run-*/snapshot.sqlite")), child.communicate(timeout=1)
        child.send_signal(interrupt)
        _, errors = child.communicate(timeout=5)
        assert child.returncode == 128 + interrupt, errors.decode("utf-8", "replace")
        assert not list(runtime.glob("run-*"))
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
