from copy import deepcopy
import os
from pathlib import Path
import sqlite3

import pytest

from raftward.audit import compare


NOW = 2_000_000_000_000_000_000


def row(**overrides):
    result = {"target": "one", "path": "/fixtures/a.sqlite", "class": "live", "size": 10000,
              "mtime_ns": NOW, "inode": 1, "mode": 0o600, "sha256": "a", "sqlite": True,
              "sqlite_magic": True, "integrity": "ok", "page_count": 3, "entropy": 2.0}
    result.update(overrides)
    return result


@pytest.mark.parametrize("rule,changes", [
    ("RF-FROZEN-CHANGED", {"class": "frozen", "sha256": "b"}),
    ("RF-SQLITE-HEADER", {"sqlite_magic": False}),
    ("RF-INTEGRITY", {"integrity": "not ok"}),
    ("RF-SHRINK", {"size": 4999}),
    ("RF-ENTROPY", {"entropy": 7.9}),
    ("RF-MODE", {"mode": 0o644}),
    ("RF-FUTURE-MTIME", {"mtime_ns": NOW + 301_000_000_000}),
])
def test_rule_positive_and_negative(rule, changes):
    old = row()
    target = {"name": "one", "class": changes.get("class", "live")}
    actual = compare({"fp": row(**changes)}, {"fp": old}, {"fp": old}, [target], NOW)
    assert rule in {f["rule"] for f in actual}
    assert rule not in {f["rule"] for f in compare({"fp": old}, {"fp": old}, {"fp": old}, [target], NOW)}


def test_deleted_positive_negative():
    old = {"fp": row()}
    target = [{"name": "one", "class": "live"}]
    assert [f["rule"] for f in compare({}, old, old, target, NOW)] == ["RF-DELETED"]
    assert compare(old, old, old, target, NOW) == []


@pytest.mark.parametrize("size,expected", [(5000, False), (4999, True), (0, True)])
def test_shrink_boundary(size, expected):
    found = compare({"fp": row(size=size)}, {"fp": row()}, {}, [{"name": "one", "class": "live"}], NOW)
    assert ("RF-SHRINK" in {f["rule"] for f in found}) == expected


def test_live_normal_change_negative():
    assert compare({"fp": row(sha256="b", mtime_ns=NOW - 1, size=11000)}, {"fp": row(mtime_ns=NOW - 2)}, {}, [{"name": "one", "class": "live"}], NOW) == []


def test_future_mtime_has_no_silent_grace_period():
    found = compare({"fp": row(mtime_ns=NOW + 1)}, {}, {}, [{"name": "one", "class": "live"}], NOW)
    assert "RF-FUTURE-MTIME" in {f["rule"] for f in found}


def test_non_sqlite_no_header_alarm():
    assert compare({"fp": row(sqlite=False, sqlite_magic=False, integrity="not checked", **{"class": "frozen"})}, {}, {}, [{"name": "one", "class": "frozen"}], NOW) == []


@pytest.mark.parametrize("mutation", ["count", "percent", "extensions", "note"])
def test_mass_change_positive_negative(mutation):
    size = 100 if mutation != "percent" else 10
    old = {str(i): row(path=f"/fixtures/{i}.txt", **{"class": "folder"}) for i in range(size)}
    new = deepcopy(old)
    if mutation in {"count", "percent"}:
        for i in range(21 if mutation == "count" else 4):
            new[str(i)]["sha256"] = "changed"
    elif mutation == "extensions":
        for i in range(11):
            new["new" + str(i)] = row(path=f"/fixtures/new{i}.locked", **{"class": "folder"})
    else:
        new["note"] = row(path="/fixtures/README_DECRYPT.txt", **{"class": "folder"})
    target = [{"name": "one", "class": "folder"}]
    assert "RF-MASS-CHANGE" in {f["rule"] for f in compare(new, old, old, target, NOW)}
    assert "RF-MASS-CHANGE" not in {f["rule"] for f in compare(old, old, old, target, NOW)}


def test_real_header_corruption(run, database):
    assert run("baseline")[0] == 0
    with database.open("r+b") as output:
        output.write(b"not a database!!")
    code, out, err = run("check")
    assert code == 1 and "RF-SQLITE-HEADER" in out and not err


def test_real_page_corruption(run, database):
    assert run("baseline")[0] == 0
    with database.open("r+b") as output:
        output.seek(4096)
        output.write(b"\xff" * 512)
    code, out, err = run("check")
    assert code == 1 and "RF-INTEGRITY" in out and not err


def test_ransomware_sim_with_rename_and_entropy(config, run, database):
    folder = database.parent / "packet"
    folder.mkdir()
    for i in range(50):
        (folder / f"{i}.txt").write_bytes(b"a" * 4096)
    config["targets"] = [{"name": "packet", "path": str(folder), "class": "folder", "owners": ["notebook"]}]
    assert run("baseline")[0] == 0
    for i in range(25):
        path = folder / f"{i}.txt"
        path.write_bytes(bytes(range(256)) * 16)
        path.rename(folder / f"{i}.locked")
    (folder / "README_DECRYPT.txt").write_text("fixture simulation")
    code, out, err = run("check")
    assert code == 1 and "RF-MASS-CHANGE" in out and "RF-ENTROPY" in out
