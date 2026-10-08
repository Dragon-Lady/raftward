import errno
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from raftward import guard
from raftward.guard import Deferred, Guard, Process, processes


def proc_tree(tmp_path):
    root = tmp_path / "proc"
    task = root / "123"
    task.mkdir(parents=True)
    (task / "comm").write_text("notebook-worker")
    (task / "cmdline").write_bytes(b"notebook-worker\0--background\0")
    (task / "stat").write_text("123 (notebook-worker) S " + "0 " * 18 + "100")
    (task / "exe").symlink_to("/usr/bin/notebook-worker")
    (task / "fd").mkdir()
    return root, task


def other_uid(monkeypatch, task):
    original = Path.stat
    def get(path, *args, **kwargs):
        value = original(path, *args, **kwargs)
        if path == task:
            return SimpleNamespace(st_uid=os.getuid() + 1, st_ino=value.st_ino)
        return value
    monkeypatch.setattr(Path, "stat", get)


def test_other_uid_exe_fd_permissions_do_not_hide_owner(tmp_path, monkeypatch, config):
    root, task = proc_tree(tmp_path)
    other_uid(monkeypatch, task)
    original = os.readlink
    def readlink(path):
        if Path(path) == task / "exe":
            raise PermissionError(errno.EACCES, "private message")
        return original(path)
    monkeypatch.setattr(os, "readlink", readlink)
    original_iter = Path.iterdir
    def entries(path):
        if path == task / "fd":
            pytest.fail("other-UID descriptor enumeration is outside available visibility")
        return original_iter(path)
    monkeypatch.setattr(Path, "iterdir", entries)
    rows = processes(root)
    assert len(rows) == 1 and rows[0].exe == "" and rows[0].fds == ()
    with pytest.raises(Deferred, match="owning-app-running"):
        Guard(config, lambda: rows).check()


@pytest.mark.parametrize("denied", ["comm", "cmdline"])
def test_other_uid_one_readable_name_still_detects_owner(tmp_path, monkeypatch, config, denied):
    root, task = proc_tree(tmp_path)
    other_uid(monkeypatch, task)
    original = guard._proc_bytes
    def read(path, limit):
        if path == task / denied:
            raise PermissionError(errno.EACCES, "denied")
        return original(path, limit)
    monkeypatch.setattr(guard, "_proc_bytes", read)
    with pytest.raises(Deferred, match="owning-app-running"):
        Guard(config, lambda: processes(root)).check()


@pytest.mark.parametrize("same_uid", [True, False])
def test_unreadable_live_identity_is_bounded_unknown(tmp_path, monkeypatch, same_uid):
    root, task = proc_tree(tmp_path)
    if not same_uid:
        other_uid(monkeypatch, task)
    original = guard._proc_bytes
    waits = []
    reads = []
    def read(path, limit):
        if path.parent == task and path.name in {"comm", "cmdline"}:
            reads.append(path.name)
            raise PermissionError(errno.EACCES, "private error")
        return original(path, limit)
    monkeypatch.setattr(guard, "_proc_bytes", read)
    monkeypatch.setattr(guard.time, "sleep", waits.append)
    with pytest.raises(Deferred, match="^process-state-unknown$"):
        processes(root)
    assert waits == [0.05, 0.05, 0.05]
    assert reads.count("comm") == reads.count("cmdline") == 4


@pytest.mark.parametrize("field", ["comm", "cmdline", "exe", "fd"])
def test_same_uid_transient_exec_permissions_are_retried(tmp_path, monkeypatch, field):
    root, task = proc_tree(tmp_path)
    original_bytes, original_link, original_iter = guard._proc_bytes, os.readlink, Path.iterdir
    failures, waits = [], []
    def fail(path):
        if Path(path) == task / field and len(failures) < 2:
            failures.append(True)
            raise PermissionError(errno.EACCES, "exec transition")
    def read(path, limit):
        fail(path)
        return original_bytes(path, limit)
    def link(path):
        fail(path)
        return original_link(path)
    def entries(path):
        fail(path)
        return original_iter(path)
    monkeypatch.setattr(guard, "_proc_bytes", read)
    monkeypatch.setattr(os, "readlink", link)
    monkeypatch.setattr(Path, "iterdir", entries)
    monkeypatch.setattr(guard.time, "sleep", waits.append)
    assert processes(root)[0].comm == "notebook-worker"
    assert waits == [0.05, 0.05]


@pytest.mark.parametrize("field", ["cmdline", "fd"])
def test_same_uid_persistent_unreadability_defers(tmp_path, monkeypatch, field):
    root, task = proc_tree(tmp_path)
    original_bytes, original_link, original_iter = guard._proc_bytes, os.readlink, Path.iterdir
    def fail(path):
        if Path(path) == task / field:
            raise PermissionError(errno.EACCES, "persistent")
    def read(path, limit):
        fail(path)
        return original_bytes(path, limit)
    def link(path):
        fail(path)
        return original_link(path)
    def entries(path):
        fail(path)
        return original_iter(path)
    monkeypatch.setattr(guard, "_proc_bytes", read)
    monkeypatch.setattr(os, "readlink", link)
    monkeypatch.setattr(Path, "iterdir", entries)
    monkeypatch.setattr(guard.time, "sleep", lambda _: None)
    reason = "process-descriptor-state-unknown" if field == "fd" else "process-state-unknown"
    with pytest.raises(Deferred, match=reason):
        processes(root)


@pytest.mark.parametrize("code", [errno.ENOENT, errno.ESRCH])
def test_disappearing_process_is_closed(tmp_path, monkeypatch, code):
    root, task = proc_tree(tmp_path)
    original = guard._proc_bytes
    def read(path, limit):
        if path == task / "cmdline":
            raise OSError(code, "process gone")
        return original(path, limit)
    monkeypatch.setattr(guard, "_proc_bytes", read)
    assert processes(root) == []


@pytest.mark.parametrize("code", [errno.ENOENT, errno.ESRCH])
def test_missing_exe_keeps_readable_owner_identity(tmp_path, monkeypatch, config, code):
    root, task = proc_tree(tmp_path)
    monkeypatch.setattr(os, "readlink", lambda _: (_ for _ in ()).throw(OSError(code, "exe gone")))
    with pytest.raises(Deferred, match="owning-app-running"):
        Guard(config, lambda: processes(root)).check()


def test_pid_reuse_is_reread(tmp_path, monkeypatch):
    root, task = proc_tree(tmp_path)
    original = guard._proc_stat
    ticks = []
    def state(path):
        ticks.append(True)
        return b"S", b"100" if len(ticks) == 1 else b"200"
    monkeypatch.setattr(guard, "_proc_stat", state)
    waits = []
    monkeypatch.setattr(guard.time, "sleep", waits.append)
    assert processes(root)[0].pid == 123
    assert len(ticks) == 4 and waits == [0.05]


@pytest.mark.parametrize("value", ["1", "2", "invisible"])
def test_hidepid_mount_defers_without_enumerating(value, monkeypatch):
    monkeypatch.setattr(guard, "_proc_bytes", lambda *_: f"1 0 0:1 / /proc rw - proc proc rw,hidepid={value}\n".encode())
    monkeypatch.setattr(Path, "iterdir", lambda _: pytest.fail("restricted process view must not be used"))
    with pytest.raises(Deferred, match="process-visibility-restricted"):
        processes()


def test_100ms_poll_and_mandatory_checks(config, monkeypatch):
    clock = [1.0]
    calls, active = [], []
    monkeypatch.setattr(guard.time, "monotonic", lambda: clock[0])
    def reader():
        calls.append(clock[0])
        return [Process("notebook-worker", "", "")] if active else []
    gate = Guard(config, reader)
    gate.check(force=False)
    clock[0] = 1.099
    gate.check(force=False)
    assert len(calls) == 1
    clock[0] = 1.101
    gate.check(force=False)
    assert len(calls) == 2
    active.append(True)
    clock[0] = 1.102
    with pytest.raises(Deferred, match="owning-app-running"):
        gate.check()  # forced I/O boundary ignores the remaining cached interval
    assert len(calls) == 3


def test_same_uid_exe_is_supplementary_after_bounded_reread(tmp_path, monkeypatch, config):
    root, task = proc_tree(tmp_path)
    original = os.readlink
    def denied(path):
        if Path(path) == task / "exe":
            raise PermissionError(errno.EACCES, "exe restricted")
        return original(path)
    monkeypatch.setattr(os, "readlink", denied)
    waits = []
    monkeypatch.setattr(guard.time, "sleep", waits.append)
    rows = processes(root)
    assert rows[0].exe == "" and waits == [0.05, 0.05, 0.05]
    with pytest.raises(Deferred, match="owning-app-running"):
        Guard(config, lambda: rows).check()


def test_kernel_protected_same_uid_fd_is_unverifiable_but_names_still_gate(tmp_path, monkeypatch, config):
    root, task = proc_tree(tmp_path)
    original_stat, original_link, original_iter = Path.stat, os.readlink, Path.iterdir
    def protected_stat(path, *args, **kwargs):
        value = original_stat(path, *args, **kwargs)
        if path == task / "fd":
            return SimpleNamespace(st_uid=0)
        return value
    def denied_link(path):
        if Path(path) == task / "exe":
            raise PermissionError(errno.EACCES, "kernel protection")
        return original_link(path)
    def no_fd_walk(path):
        if path == task / "fd":
            pytest.fail("protected descriptor directory must not be enumerated")
        return original_iter(path)
    monkeypatch.setattr(Path, "stat", protected_stat)
    monkeypatch.setattr(os, "readlink", denied_link)
    monkeypatch.setattr(Path, "iterdir", no_fd_walk)
    rows = processes(root)
    assert len(rows) == 1 and rows[0].fd_check == "unverifiable" and rows[0].fds == ()
    with pytest.raises(Deferred, match="owning-app-running"):
        Guard(config, lambda: rows).check()
    config["owners"]["notebook"] = ["unrelated-owner"]
    gate = Guard(config, lambda: rows)
    gate.check()
    assert gate.open_file_check == "unverifiable"


@pytest.mark.parametrize("denial", [errno.EACCES, errno.EPERM])
@pytest.mark.parametrize("extra_field", [b"CapPrm", b"CapEff"])
def test_extra_capability_same_uid_fd_readlink_is_unverifiable(tmp_path, monkeypatch, config, denial, extra_field):
    root, task = proc_tree(tmp_path)
    (task / "fd" / "4").symlink_to("/tmp/closed-fixture")
    original_bytes, original_link = guard._proc_bytes, os.readlink
    waits = []
    def read(path, limit):
        if path == task / "status":
            masks = {b"CapPrm": b"0", b"CapEff": b"0"}
            masks[extra_field] = b"800000000"  # CAP_WAKE_ALARM
            return b"\n".join(key + b":\t" + value for key, value in masks.items()) + b"\n"
        if path == Path("/proc/self/status"):
            return b"CapPrm:\t0\nCapEff:\t0\n"
        return original_bytes(path, limit)
    def link(path):
        if Path(path).parent == task / "fd":
            raise PermissionError(denial, "kernel-protected link")
        return original_link(path)
    monkeypatch.setattr(guard, "_proc_bytes", read)
    monkeypatch.setattr(os, "readlink", link)
    monkeypatch.setattr(guard.time, "sleep", waits.append)
    rows = processes(root)
    assert len(rows) == 1 and rows[0].fd_check == "unverifiable" and rows[0].fds == ()
    assert waits == [0.05, 0.05, 0.05]
    with pytest.raises(Deferred, match="owning-app-running"):
        Guard(config, lambda: rows).check()
    config["owners"]["notebook"] = ["unrelated-owner"]
    gate = Guard(config, lambda: rows)
    gate.check()
    assert gate.open_file_check == "unverifiable"


@pytest.mark.parametrize("other_status", [b"CapPrm:\t0\nCapEff:\t0\n", b"CapPrm:\t0\n"])
def test_same_uid_fd_readlink_denial_without_proven_extra_caps_defers(tmp_path, monkeypatch, other_status):
    root, task = proc_tree(tmp_path)
    (task / "fd" / "4").symlink_to("/tmp/closed-fixture")
    original_bytes, original_link = guard._proc_bytes, os.readlink
    def read(path, limit):
        if path == task / "status":
            return other_status
        if path == Path("/proc/self/status"):
            return b"CapPrm:\t0\nCapEff:\t0\n"
        return original_bytes(path, limit)
    def link(path):
        if Path(path).parent == task / "fd":
            raise PermissionError(errno.EACCES, "ordinary denial")
        return original_link(path)
    monkeypatch.setattr(guard, "_proc_bytes", read)
    monkeypatch.setattr(os, "readlink", link)
    monkeypatch.setattr(guard.time, "sleep", lambda _: None)
    with pytest.raises(Deferred, match="^process-descriptor-state-unknown$"):
        processes(root)


def test_poll_interval_is_measured_after_slow_reader(config, monkeypatch):
    clock = [1.0]
    calls = []
    monkeypatch.setattr(guard.time, "monotonic", lambda: clock[0])
    def reader():
        calls.append(True)
        clock[0] += 0.150
        return []
    gate = Guard(config, reader)
    gate.check(force=False)
    clock[0] = 1.249
    gate.check(force=False)
    assert len(calls) == 1
    clock[0] = 1.251
    gate.check(force=False)
    assert len(calls) == 2
