import hashlib
from pathlib import Path
import sqlite3
try:
    import tomllib
except ImportError:
    import tomli as tomllib

from raftward import API_VERSION, __version__, gate, verify
from raftward.guard import Deferred, Process


def test_runtime_version_matches_package_metadata():
    metadata = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
    assert __version__ == metadata["project"]["version"] == "0.1.4"


def test_public_api_passes_frozen_copy_and_rejects_change(tmp_path):
    assert API_VERSION == 1
    source = tmp_path / "frozen.sqlite"
    with sqlite3.connect(source) as db:
        db.execute("CREATE TABLE messages (text TEXT)")
        db.execute("INSERT INTO messages VALUES ('private canary')")
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    runtime = tmp_path / "runtime"
    good = verify(source, expected_sha256=digest, expected_size=len(data), runtime=runtime)
    assert good.status == "pass"
    assert good.page_count > 0
    assert "private canary" not in repr(good)
    assert verify(source, expected_sha256="0" * 64, runtime=runtime).reason == "frozen-copy-changed"
    assert verify(source, expected_sha256=None, runtime=runtime).status == "inconclusive"
    assert list(runtime.glob("run-*")) == []


def test_public_api_rejects_corrupt_sqlite_without_leaking_data(tmp_path):
    source = tmp_path / "frozen.sqlite"
    source.write_bytes(b"not sqlite private canary")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    result = verify(source, expected_sha256=digest, runtime=tmp_path / "runtime")
    assert result.status == "fail"
    assert result.reason == "sqlite-header-invalid"
    assert "private canary" not in repr(result)


def test_gate_distinguishes_known_blocker_and_unknown(tmp_path):
    source = tmp_path / "original.sqlite"
    assert gate(source, ["notes-app"], reader=lambda: []).status == "pass"
    busy = gate(source, ["notes-app"], reader=lambda: [Process("notes-app", "", "")])
    assert (busy.status, busy.reason) == ("fail", "owning-app-running")

    def unknown():
        raise Deferred("process-state-unknown")

    result = gate(source, ["notes-app"], reader=unknown)
    assert (result.status, result.reason) == ("inconclusive", "process-state-unknown")
    protected = gate(source, ["notes-app"], reader=lambda: [Process("systemd", "", "", fd_check="unverifiable")])
    assert (protected.status, protected.open_file_check) == ("pass", "unverifiable")


def test_api_rejects_glob_paths_and_unexpected_errors(tmp_path, monkeypatch):
    from raftward import api
    path = tmp_path / "notes[old].sqlite"
    assert gate(path, ["notes-app"], reader=lambda: []).status == "inconclusive"
    assert verify(path, expected_sha256="0" * 64, runtime=tmp_path / "runtime").status == "inconclusive"

    def broken():
        raise RuntimeError("sensitive path should not escape")

    assert gate(tmp_path / "ok.sqlite", ["notes-app"], reader=broken).reason == "process-state-unknown"
    monkeypatch.setattr(api.Scanner, "scan", lambda *a, **k: broken())
    result = verify(tmp_path / "ok.sqlite", expected_sha256="0" * 64,
                    runtime=tmp_path / "runtime")
    assert (result.status, result.reason) == ("inconclusive", "verify-error")
