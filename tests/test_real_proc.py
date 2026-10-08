"""Read real /proc records through an explicitly controlled fixture view.

These tests cover real permissions/churn, not full-host closure. Kernel-protected
same-UID descriptors are reported as unverifiable while names still gate.
"""
import errno
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

from raftward.config import validate
from raftward.guard import Deferred, Guard, _extra_capabilities, _proc_stat, processes as real_processes
from raftward.scanner import Scanner


def fixture_config(config):
    value = dict(config)
    value["owners"] = {"fixture": ["raft-fixture-absent-" + str(os.getpid())]}
    value["transfer_commands"] = ["raft-fixture-transfer-absent-" + str(os.getpid())]
    value["targets"] = [dict(row, owners=["fixture"]) for row in config["targets"]]
    return validate(value)


def real_root_view(tmp_path):
    roots = []
    for task in Path("/proc").iterdir():
        try:
            if task.name.isdecimal() and task.stat().st_uid == 0:
                roots.append(task)
        except (FileNotFoundError, ProcessLookupError):
            continue
    if os.getuid() == 0 or not roots:
        pytest.skip("requires a normal user with a visible root-owned process")
    view = tmp_path / "controlled-proc-view"
    view.mkdir()
    task = min(roots, key=lambda p: int(p.name))
    (view / task.name).symlink_to(task, target_is_directory=True)
    return view, task


def test_real_proc_root_process_does_not_make_closed_fixture_unknown(config, database, tmp_path):
    view, root_task = real_root_view(tmp_path)
    rows = real_processes(view)
    assert any(row.uid == 0 and row.pid == int(root_task.name) for row in rows)
    cfg = fixture_config(config)
    before = (database.read_bytes(), database.stat().st_mtime_ns)
    scan = Scanner(cfg, Guard(cfg, lambda: real_processes(view)), b"k" * 32,
                   Path(os.environ["XDG_RUNTIME_DIR"]) / "raftward")
    entries, missing = scan.scan(cfg["targets"], {})
    assert not missing and next(iter(entries.values()))["integrity"] == "ok"
    assert (database.read_bytes(), database.stat().st_mtime_ns) == before
    assert not list(scan.runtime.iterdir())


def test_real_proc_other_uid_owner_detected_with_unreadable_exe(config, monkeypatch, tmp_path):
    view, task = real_root_view(tmp_path)
    target = real_processes(view)[0]
    cfg = fixture_config(config)
    cfg["owners"]["fixture"] = [target.comm]
    original = os.readlink
    def deny(path, *args, **kwargs):
        if Path(path) == view / task.name / "exe":
            raise PermissionError(errno.EACCES, "fixture ptrace restriction")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(os, "readlink", deny)
    with pytest.raises(Deferred, match="owning-app-running"):
        Guard(cfg, lambda: real_processes(view)).check()


def test_real_proc_churn_allows_closed_fixture_scans(config, database, tmp_path):
    view, _ = real_root_view(tmp_path)
    cfg = fixture_config(config)
    stop = threading.Event()
    launches, errors = [], []
    def churn():
        try:
            while not stop.is_set():
                # Direct harmless local Python invocation; no shell or network.
                child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.05)"],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                link = view / str(child.pid)
                try:
                    link.symlink_to(Path("/proc") / str(child.pid), target_is_directory=True)
                    child.wait(timeout=5)
                    launches.append(True)
                finally:
                    if child.poll() is None:
                        child.terminate()
                        child.wait(timeout=5)
                    link.unlink(missing_ok=True)
                stop.wait(0.95)
        except Exception as exc:
            errors.append(type(exc).__name__)
    worker = threading.Thread(target=churn)
    worker.start()
    before = (database.read_bytes(), database.stat().st_mtime_ns)
    completed = 0
    try:
        deadline = time.monotonic() + 2.3
        while time.monotonic() < deadline:
            scan = Scanner(cfg, Guard(cfg, lambda: real_processes(view)), b"k" * 32,
                           Path(os.environ["XDG_RUNTIME_DIR"]) / "raftward")
            entries, missing = scan.scan(cfg["targets"], {})
            assert not missing and next(iter(entries.values()))["integrity"] == "ok"
            completed += 1
    finally:
        stop.set()
        worker.join(timeout=5)
    assert not worker.is_alive() and not errors
    assert completed >= 1 and len(launches) >= 3
    assert (database.read_bytes(), database.stat().st_mtime_ns) == before
    assert not list(scan.runtime.iterdir())


def test_real_proc_full_host_kernel_protected_fd_is_unverifiable(config):
    denied, protected = [], []
    for task in Path("/proc").iterdir():
        try:
            if not task.name.isdecimal() or int(task.name) == os.getpid() or task.stat().st_uid != os.getuid():
                continue
            if _proc_stat(task)[0] in {b"Z", b"X"}:
                continue  # zombie/exit tasks do not own live descriptors
            fd_owner = (task / "fd").stat().st_uid
            if fd_owner == 0 and os.getuid() != 0:
                protected.append(int(task.name))
                continue
            for descriptor in (task / "fd").iterdir():
                try:
                    os.readlink(descriptor)
                except OSError as exc:
                    if exc.errno in {errno.EACCES, errno.EPERM}:
                        (protected if _extra_capabilities(task) else denied).append(int(task.name))
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EPERM}:
                denied.append(task.name)
    if not denied:
        rows = real_processes()
        if not protected:
            pytest.skip("host has no protected same-UID descriptor directory")
        assert any(row.pid in protected and row.fd_check == "unverifiable" for row in rows)
        cfg = fixture_config(config)
        gate = Guard(cfg, lambda: rows)
        gate.check()
        assert gate.open_file_check == "unverifiable"
    else:
        with pytest.raises(Deferred, match="process-descriptor-state-unknown"):
            real_processes()
