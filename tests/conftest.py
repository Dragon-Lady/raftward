import os
from pathlib import Path
import sqlite3

import pytest

from raftward import cli
from raftward.config import validate
from raftward.guard import Guard


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local/state"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    # Fixtures never enumerate the host's /proc or touch real application data.
    monkeypatch.setattr("raftward.guard.processes", lambda: [])
    monkeypatch.setattr(os, "nice", lambda value: 0)
    return home


@pytest.fixture
def database(isolated_home):
    path = isolated_home / "fixtures/db.sqlite"
    path.parent.mkdir(mode=0o700)
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT)")
    db.executemany("INSERT INTO items(value) VALUES (?)", [("content-" + str(i),) for i in range(1000)])
    db.commit()
    db.close()
    return path


@pytest.fixture
def config(database):
    return validate({"owners": {"notebook": ["notebook-worker"]},
                     "targets": [{"name": "notes", "path": str(database), "class": "live", "owners": ["notebook"]}]})


@pytest.fixture
def run(config, monkeypatch, capsys):
    monkeypatch.setattr(cli, "load", lambda path: validate(config))

    def invoke(*args):
        code = cli.main(list(args))
        output = capsys.readouterr()
        return code, output.out, output.err
    return invoke
