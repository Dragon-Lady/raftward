import json
import os
from pathlib import Path
import sqlite3

import pytest

from raftward import cli
from raftward.guard import Deferred, Guard, Process
from raftward.safety import SafeError, Store
from raftward.scanner import Scanner


def test_redaction_cannot_suppress_deleted_or_frozen_findings(config, database, run, monkeypatch):
    # A valid identifier can equal an alert credential. Redaction must not change
    # internal target identity or protocol enums used by comparisons.
    token = "gh" + "p_" + "CANARYVALUE" * 4
    config["targets"][0]["name"] = token
    config["targets"][0]["class"] = "frozen"
    config["alert_ntfy_token_env"] = "TEST_SECRET"
    monkeypatch.setenv("TEST_SECRET", "frozen")
    code, out, err = run("baseline")
    assert code == 0 and token not in out + err
    db = sqlite3.connect(database)
    db.execute("INSERT INTO items(value) VALUES ('changed')")
    db.commit()
    db.close()
    code, out, err = run("check")
    assert code == 1 and "RF-FROZEN-CHANGED" in out
    database.unlink()
    code, out, err = run("check")
    assert code == 1 and "RF-DELETED" in out
    state = Path(os.environ["XDG_STATE_HOME"]) / "raftward"
    assert all(token.encode() not in p.read_bytes() for p in state.iterdir())


def test_every_format_target_management_canary(run, database):
    token = "gh" + "p_" + "CANARYVALUE" * 4
    for index, fmt in enumerate(("text", "json", "md", "html")):
        name = "backup" + str(index)
        for args in (("targets", "add", name, str(database.parent / (name + ".sqlite")), "--owner", "notebook"),
                     ("targets", "list"), ("targets", "remove", name)):
            code, out, err = run(*args, "--format", fmt)
            assert code == 0 and token not in out + err
        code, out, err = run("targets", "add", "bad", str(database.parent / token), "--owner", "notebook", "--format", fmt)
        assert code == 2 and token not in out + err


def test_empty_folder_is_not_deleted(config, database, run):
    folder = database.parent / "empty"
    folder.mkdir()
    config["targets"] = [{"name": "empty", "class": "folder", "path": str(folder), "owners": ["notebook"]}]
    code, out, err = run("baseline")
    assert code == 0 and "RF-DELETED" not in out


def test_accept_known_folder_deletion_but_not_missing_target(config, database, run):
    folder = database.parent / "packet"
    folder.mkdir()
    content = folder / "item.txt"
    content.write_text("known fixture")
    config["targets"] = [{"name": "packet", "class": "folder", "path": str(folder), "owners": ["notebook"]}]
    assert run("baseline")[0] == 0
    content.unlink()
    assert run("check")[0] == 1
    assert run("accept", "packet")[0] == 0
    assert run("check")[0] == 0
    folder.rmdir()
    assert run("accept", "packet")[0] == 1


def test_frozen_glob_new_file_is_a_change(config, database, run):
    config["targets"][0].update({"path": str(database.parent / "*.sqlite"), "class": "frozen"})
    assert run("baseline")[0] == 0
    other = database.parent / "extra.sqlite"
    other.write_bytes(database.read_bytes())
    code, out, err = run("check")
    assert code == 1 and "RF-FROZEN-CHANGED" in out


def test_glob_and_folder_symlink_deferral(config, database, run):
    config["targets"][0]["path"] = str(database.parent / "*.sqlite")
    assert run("baseline")[0] == 0
    link = database.parent / "another.sqlite"
    link.symlink_to(database)
    assert run("check")[0] == 3


def test_runtimedir_overlap_defers_before_source_open(config, database, run, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(database.parent.parent))
    config["targets"] = [{"name": "folder", "class": "folder", "path": str(database.parent.parent), "owners": ["notebook"]}]
    # State also falls within this broad target; even key creation is refused.
    code, out, err = run("check")
    assert code == 2 and "overlap" in err


def test_no_stat_fallback_midrun_other_target(config, database, monkeypatch):
    other = database.parent / "other.sqlite"
    other.write_bytes(database.read_bytes())
    config["targets"].append(dict(config["targets"][0], name="other", path=str(other)))
    active = []
    guard = Guard(config, lambda: [Process("notebook-worker", "", "")] if active else [])
    scan = Scanner(config, guard, b"k" * 32, Path(os.environ["XDG_RUNTIME_DIR"]) / "raftward")
    original_read, original_stat = os.read, os.stat
    def read(fd, n):
        block = original_read(fd, n)
        if os.readlink(f"/proc/self/fd/{fd}") == str(database):
            active.append(True)
        return block
    def stat(path, *a, **kw):
        if active and str(path) in (str(database), str(other), database.name, other.name):
            pytest.fail("target stat continued after owner appeared")
        return original_stat(path, *a, **kw)
    monkeypatch.setattr(os, "read", read)
    monkeypatch.setattr(os, "stat", stat)
    entries, missing = scan.scan(config["targets"], {})
    assert not entries and not missing
    assert {item["name"] for item in scan.skipped} == {"notes", "other"}


def test_timer_text_contains_actual_unit_lines(run):
    code, out, err = run("print-timer", "--interval", "5m")
    assert code == 0 and "\n[Service]\n" in out and "OnUnitActiveSec=300s\n" in out


def test_missing_key_and_unsafe_state_refused(run):
    assert run("baseline")[0] == 0
    state = Path(os.environ["XDG_STATE_HOME"]) / "raftward"
    (state / "fp.key").unlink()
    assert run("check")[0] == 2


def test_symlinked_output_parent_cannot_overwrite(database, run):
    link = database.parent.parent / "out-link"
    link.symlink_to(database.parent, target_is_directory=True)
    code, out, err = run("status", "--output", str(link / "report"))
    assert code == 2 and not (database.parent / "report").exists()


def test_report_retention(run, monkeypatch):
    assert run("baseline")[0] == 0
    state = Path(os.environ["XDG_STATE_HOME"]) / "raftward"
    store = Store(state)
    old = json.loads((state / "last.json").read_text())
    old["time"] = 1
    from raftward.safety import write_private
    write_private(state / "history.jsonl", json.dumps(old) + "\n", replace=True)
    assert run("check")[0] == 0
    assert len((state / "history.jsonl").read_text().splitlines()) == 1
