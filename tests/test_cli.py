import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import stat
import subprocess

import pytest

from raftward import cli
from raftward.config import load, validate
from raftward.guard import Process
from raftward.safety import Redactor, SafeError, Store


def state():
    return Path(os.environ["XDG_STATE_HOME"]) / "raftward"


def test_baseline_check_accept(config, database, run):
    config["targets"][0]["class"] = "frozen"
    assert run("baseline")[0] == 0
    assert run("check")[0] == 0
    db = sqlite3.connect(database)
    db.execute("INSERT INTO items(value) VALUES ('ordinary edit')")
    db.commit()
    db.close()
    code, out, err = run("check")
    assert code == 1 and "RF-FROZEN-CHANGED" in out
    assert run("accept", "notes", "--reason", "known-good-import")[0] == 0
    assert run("check")[0] == 0
    record = json.loads((state() / "accepts.jsonl").read_text())
    assert record["reason_fp"].startswith("fp:")
    assert "known-good-import" not in (state() / "accepts.jsonl").read_text()


def test_live_ordinary_edit(config, database, run):
    assert run("baseline")[0] == 0
    db = sqlite3.connect(database)
    db.execute("INSERT INTO items(value) VALUES ('ordinary edit')")
    db.commit()
    db.close()
    assert run("check")[0] == 0


def test_sigint_during_integrity_cancels_without_damage_report(database, run, monkeypatch):
    original = cli.Scanner

    class InterruptDuringIntegrity(original):
        triggered = False

        def sqlite_copy(self, copy):
            self.in_integrity = True
            try:
                return super().sqlite_copy(copy)
            finally:
                self.in_integrity = False

        def checkpoint(self, force=False):
            if getattr(self, "in_integrity", False) and not force and not type(self).triggered:
                type(self).triggered = True
                signal.raise_signal(signal.SIGINT)
            return super().checkpoint(force)

    monkeypatch.setattr(cli, "Scanner", InterruptDuringIntegrity)
    before = database.read_bytes()
    code, out, err = run("check", "--format", "json")
    assert InterruptDuringIntegrity.triggered
    assert code == 130 and not out and "interrupted" in err
    assert "RF-INTEGRITY" not in err
    assert not (state() / "last.json").exists()
    assert database.read_bytes() == before
    assert not list((Path(os.environ["XDG_RUNTIME_DIR"]) / "raftward").iterdir())


def test_baseline_force_required(run):
    assert run("baseline")[0] == 0
    assert run("baseline")[0] == 2
    assert run("baseline", "--force")[0] == 0


def test_accept_rejects_corruption(database, run):
    assert run("baseline")[0] == 0
    before = (state() / "baseline.json").read_bytes()
    database.write_bytes(b"corrupt")
    code, out, err = run("accept", "notes")
    assert code == 1 and "baseline-refused" in out
    assert (state() / "baseline.json").read_bytes() == before


def test_targets_cli(run, database):
    assert run("targets", "list")[0] == 0
    assert run("targets", "add", "copy", str(database.parent / "copy.sqlite"), "--owner", "notebook", "--sqlite")[0] == 0
    assert "copy" in run("targets", "list")[1]
    assert run("targets", "remove", "copy")[0] == 0
    assert "copy" not in run("targets", "list")[1]


@pytest.mark.parametrize("format", ["text", "json", "md", "html"])
def test_every_command_canary_no_network_modes(config, database, run, monkeypatch, format):
    # Assemble markers so source fixtures themselves do not contain live-looking tokens.
    token = "gh" + "p_" + "CANARYVALUE" * 4
    webhook = "https://hooks.example.invalid/" + token
    monkeypatch.setenv("RAFT_TEST_WEBHOOK", webhook)
    db = sqlite3.connect(database)
    db.execute("INSERT INTO items(value) VALUES (?)", (token,))
    db.commit()
    db.close()
    def forbidden(*a, **kw):
        pytest.fail("offline command attempted a network connection or subprocess")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    commands = [("baseline",), ("baseline", "export"), ("check",), ("guard",), ("status",),
                ("report",), ("report", "--send"), ("print-timer",), ("targets", "list"),
                ("accept", "notes", "--reason", token)]
    for index, command in enumerate(commands):
        report = database.parent.parent / f"report-{format}-{index}"
        code, out, err = run(*command, "--format", format, "--output", str(report))
        assert code == 0, (command, out, err)
        assert token not in out + err + report.read_text()
        assert stat.S_IMODE(report.stat().st_mode) == 0o600
    assert stat.S_IMODE(state().stat().st_mode) == 0o700
    for path in state().rglob("*"):
        if path.is_file():
            assert token.encode() not in path.read_bytes()
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list((Path(os.environ["XDG_RUNTIME_DIR"]) / "raftward").iterdir())


def test_html_escape_path(config, database, run):
    folder = database.parent / "<script>alert(1)<"
    folder.mkdir()
    target = folder / "script>.txt"
    target.write_text("fixture")
    config["targets"] = [{"name": "html", "path": str(target), "class": "frozen", "owners": ["notebook"]}]
    code, out, err = run("baseline", "--format", "html")
    assert code == 0 and "&lt;script&gt;alert(1)&lt;" in out
    assert "<script>" not in out


def test_output_cannot_touch_target(config, database, run):
    before = database.read_bytes()
    assert run("check", "--output", str(database))[0] == 2
    assert database.read_bytes() == before


def test_output_under_watched_folder_refused(config, database, run):
    config["targets"] = [{"name": "folder", "path": str(database.parent), "class": "folder", "owners": ["notebook"]}]
    report = database.parent / "new-report.txt"
    assert run("check", "--output", str(report))[0] == 2
    assert not report.exists()


def test_existing_output_never_overwritten(database, run):
    report = database.parent.parent / "report.txt"
    report.write_text("existing")
    assert run("status", "--output", str(report))[0] == 2
    assert report.read_text() == "existing"


def test_deferred_24h_alert_once(config, monkeypatch, run):
    monkeypatch.setattr("raftward.guard.processes", lambda: [Process("notebook-worker", "", "")])
    clock = [1000.0]
    monkeypatch.setattr(cli.time, "time", lambda: clock[0])
    assert run("check")[0] == 3
    clock[0] += 86401
    code, out, err = run("check")
    assert code == 3 and "RF-DEFERRED" in out
    clock[0] += 86401
    code, out, err = run("check")
    assert code == 3 and "RF-DEFERRED" not in out
    monkeypatch.setattr("raftward.guard.processes", lambda: [])
    assert run("check")[0] == 1  # fixture mtime is future relative to controlled clock
    assert json.loads((state() / "deferred.json").read_text()) == {}


def test_missing_runtime_defers(run, monkeypatch):
    monkeypatch.delenv("XDG_RUNTIME_DIR")
    code, out, err = run("check")
    assert code == 3 and "xdg-runtime-dir-required" in out


def test_usage_does_not_echo_canary(run):
    token = "secret-not-an-option"
    code, out, err = run("check", "--" + token)
    assert code == 2 and token not in out + err


def test_config_modes_and_validation(isolated_home):
    path = isolated_home / "config.toml"
    path.write_text('machines = ["local"]\n')
    path.chmod(0o644)
    with pytest.raises(SafeError, match="0600"):
        load(path)
    path.chmod(0o600)
    assert load(path)["machines"] == ["local"]
    with pytest.raises(SafeError):
        validate({"targets": [{"name": "bad", "path": "/fixtures/db", "class": "live", "owners": []}]})


def test_persistent_transfer_24h_notice_explains_mount_daemon_deferral(run, monkeypatch):
    monkeypatch.setattr("raftward.guard.processes", lambda: [Process("rclone", "", "rclone mount")])
    clock = [1000.0]
    monkeypatch.setattr(cli.time, "time", lambda: clock[0])
    assert run("check")[0] == 3
    clock[0] += 86401
    code, out, err = run("check", "--format", "json")
    data = json.loads(out)
    assert code == 3 and not err
    assert "persistent mounts/daemons" in data["alerts"]["messages"][0]
    assert "transfer-running" in data["alerts"]["messages"][0]
