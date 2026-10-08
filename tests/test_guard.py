import os
import json
from pathlib import Path

import pytest

from raftward import cli
from raftward.config import validate
from raftward.guard import Deferred, Guard, Process, processes


@pytest.mark.parametrize("name", ["cursor", "cursor-agent", "codex", "notebook-worker"])
def test_any_owner_or_worker_stops_its_target_before_stat(database, config, name, monkeypatch, run):
    config["owners"] = {"app": [name.split("-agent")[0]]}
    config["targets"][0]["owners"] = ["app"]
    monkeypatch.setattr("raftward.guard.processes", lambda: [Process(name, "/usr/bin/" + name, name)])
    original_stat, original_open = os.stat, os.open
    accesses = []

    def watch_stat(path, *args, **kwargs):
        if str(path) in (str(database), database.name):
            accesses.append("stat")
        return original_stat(path, *args, **kwargs)

    def watch_open(path, *args, **kwargs):
        if str(path) in (str(database), database.name):
            accesses.append("open")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", watch_stat)
    monkeypatch.setattr(os, "open", watch_open)
    code, out, err = run("check", "--format", "json")
    assert code == 3 and "owning-app-running" in out
    assert not accesses and not err


def test_target_filter_checks_only_selected_owner(config, database, monkeypatch, run):
    config["owners"]["other"] = ["other-agent"]
    config["targets"].append({"name": "other", "path": str(database.parent / "other.sqlite"), "class": "live", "owners": ["other"]})
    monkeypatch.setattr("raftward.guard.processes", lambda: [Process("other-agent", "", "")])
    assert run("check", "--target", "notes")[0] == 0
    code, out, _ = run("check", "--target", "other", "--format", "json")
    assert code == 3 and '"name": "other"' in out and '"reason": "owning-app-running"' in out


def test_two_databases_one_running_owner_only_skips_its_database(config, database, monkeypatch, run):
    other = database.parent / "other.sqlite"
    other.write_bytes(database.read_bytes())
    config["owners"]["other"] = ["other-worker"]
    config["targets"].append({"name": "other", "path": str(other), "class": "live", "owners": ["other"], "sqlite": True})
    monkeypatch.setattr("raftward.guard.processes", lambda: [Process("notebook-worker", "", "")])
    original_open = os.open
    def no_owned_open(path, flags, *args, **kwargs):
        assert str(path) not in {str(database), database.name}
        return original_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", no_owned_open)
    code, out, err = run("check", "--format", "json")
    report = json.loads(out)
    assert code == 3 and not err and report["status"] == "partial"
    assert report["skipped"] == [{"name": "notes", "reason": "owning-app-running"}]
    assert len(report["entries"]) == 1
    assert next(iter(report["entries"].values()))["label"] == "other"
    assert next(iter(report["entries"].values()))["integrity"] == "ok"


def test_protected_owner_reports_unverifiable_on_skipped_database(config, monkeypatch, run):
    monkeypatch.setattr("raftward.guard.processes", lambda: [
        Process("notebook-worker", "", "", fd_check="unverifiable")])
    code, out, err = run("check", "--format", "json")
    report = json.loads(out)
    assert code == 3 and not err
    assert report["skipped"] == [{"name": "notes", "reason": "owning-app-running"}]
    assert report["open_file_check"] == "unverifiable"


@pytest.mark.parametrize("proc,reason", [
    (Process("rsync", "", "rsync"), "transfer-running"),
    (Process("rclone", "", "rclone copy"), "transfer-running"),
    (Process("worker", "", "", ("PLACEHOLDER",)), "target-handle-open"),
])
def test_process_guards(config, database, proc, reason):
    if proc.fds:
        proc = Process(proc.comm, proc.exe, proc.cmdline, (str(database) + "-wal",))
    with pytest.raises(Deferred, match=reason):
        Guard(config, lambda: [proc]).check()
    Guard(config, lambda: []).check()


def test_only_own_pid_is_excluded_not_parent_or_workers(config, database):
    Guard(config, lambda: [Process("raftward", "", "", (str(database),), os.getpid())]).check()
    Guard(config, lambda: [Process("notebook-worker", "", "", (), os.getpid())]).check()
    with pytest.raises(Deferred, match="owning-app"):
        Guard(config, lambda: [Process("notebook-worker", "", "", (), os.getppid())]).check()


def test_unknown_remote_stops_before_process_and_target_reads(config):
    config["machines"] = ["local", "remote"]
    def forbidden():
        pytest.fail("must not proceed after remote state is unknown")
    with pytest.raises(Deferred, match="remote-process-state-unknown"):
        Guard(config, forbidden).check()


def test_unknown_local_defers(config):
    def reader():
        raise PermissionError("private-canary-error")
    with pytest.raises(Deferred, match="process-state-unknown"):
        Guard(config, reader).check()


def test_transfer_lock(config, database):
    path = database.parent / "transfer.lock"
    config["transfer_locks"] = [str(path)]
    Guard(config, lambda: []).check()
    path.touch()
    with pytest.raises(Deferred, match="transfer-lock-present"):
        Guard(config, lambda: []).check()
