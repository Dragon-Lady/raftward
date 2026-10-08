"""Small, explicit fail-closed API for callers with their own frozen copies.

``gate`` inspects process state without statting the target. ``verify`` reads
only a caller-owned frozen SQLite copy. Neither function reads Raft Ward's
configuration or state, sends alerts, or creates a baseline.
"""
from dataclasses import dataclass
import os
from pathlib import Path
import re
import sys

from .config import validate
from .guard import Deferred, Guard
from .safety import SafeError
from .scanner import Scanner


API_VERSION = 1
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_KNOWN_BLOCKERS = {"owning-app-running", "target-handle-open", "transfer-running",
                   "transfer-directory-in-use", "transfer-lock-present"}


@dataclass(frozen=True)
class Result:
    """No source paths, process arguments, or file contents in public results."""

    status: str  # pass, fail, inconclusive
    reason: str
    open_file_check: str = "not-applicable"
    sha256: str | None = None
    page_count: int | None = None

    @property
    def passed(self) -> bool:
        return self.status == "pass"


def gate(path, owners, *, transfer_commands=(), transfer_dirs=(),
         transfer_locks=(), reader=None):
    """Return a fresh local owner/descriptor gate for one path.

    ``owners`` is a nonempty sequence of process-name fragments including
    workers. A protected same-UID process is name-gated under Raft Ward's
    approved rule, with ``open_file_check='unverifiable'`` disclosed.
    """
    if sys.platform != "linux":
        return Result("inconclusive", "unsupported-platform")
    try:
        if (not isinstance(path, (str, os.PathLike)) or not str(path)
                or any(c in str(path) for c in "*?[]")
                or not isinstance(owners, (list, tuple)) or not owners
                or any(not isinstance(o, str) or not o or "\x00" in o for o in owners)):
            return Result("inconclusive", "invalid-gate-input")
        cfg = validate({
            "owners": {"target": list(owners)},
            "machines": ["local"],
            "targets": [{"name": "target", "path": str(path), "class": "frozen",
                         "sqlite": True, "owners": ["target"]}],
            "transfer_commands": list(transfer_commands),
            "transfer_dirs": list(transfer_dirs),
            "transfer_locks": list(transfer_locks),
        })
        guard = Guard(cfg, reader)
        guard.check(force=True)
        return Result("pass", "ok", guard.open_file_check)
    except Deferred as exc:
        reason = str(exc)
        return Result("fail" if reason in _KNOWN_BLOCKERS else "inconclusive", reason)
    except (SafeError, OSError, TypeError, ValueError, KeyError):
        return Result("inconclusive", "gate-error")
    except Exception:
        return Result("inconclusive", "gate-error")


def verify(path, *, expected_sha256, runtime, expected_size=None,
           baseline_entropy=None):
    """Check a frozen, caller-owned SQLite copy against an expected digest.

    The expected digest must be captured independently (e.g. while making the
    copy, or from a verified transfer manifest). This proves byte equality and
    SQLite structural integrity; it cannot establish a semantic trusted
    baseline or detect a mass change in a single database.
    """
    if sys.platform != "linux":
        return Result("inconclusive", "unsupported-platform")
    if not isinstance(expected_sha256, str) or not _DIGEST.fullmatch(expected_sha256):
        return Result("inconclusive", "expected-digest-required")
    if expected_size is not None and (type(expected_size) is not int or expected_size < 0):
        return Result("inconclusive", "invalid-expected-size")
    if baseline_entropy is not None and (not isinstance(baseline_entropy, (int, float))
                                         or not 0 <= baseline_entropy <= 8):
        return Result("inconclusive", "invalid-baseline-entropy")
    try:
        if (not isinstance(path, (str, os.PathLike)) or not str(path)
                or any(c in str(path) for c in "*?[]")):
            return Result("inconclusive", "invalid-frozen-path")
        path = Path(os.path.abspath(os.path.expanduser(str(path))))
        cfg = validate({
            "owners": {"snapshot": ["__raftward_private_snapshot__"]},
            "machines": ["local"],
            "targets": [{"name": "snapshot", "path": str(path), "class": "frozen",
                         "sqlite": True, "owners": ["snapshot"]}],
            "transfer_commands": [],
        })
        # The source is already a private frozen copy; its original was gated
        # separately. Scanner's file/type/sidecar and SQLite checks still run.
        scanner = Scanner(cfg, Guard(cfg, lambda: []), b"\0" * 32, runtime)
        entries, missing = scanner.scan(cfg["targets"], {})
        if missing or len(entries) != 1 or scanner.skipped:
            return Result("fail", "frozen-copy-missing")
        row = next(iter(entries.values()))
        digest = row["sha256"]
        if digest != expected_sha256 or (expected_size is not None and row["size"] != expected_size):
            return Result("fail", "frozen-copy-changed", sha256=digest)
        if not row["sqlite_magic"]:
            return Result("fail", "sqlite-header-invalid", sha256=digest)
        if row["integrity"] != "ok":
            return Result("fail", "sqlite-integrity-failed", sha256=digest)
        if baseline_entropy is not None and baseline_entropy < 7.0 and row["entropy"] > 7.5:
            return Result("fail", "entropy-increase", sha256=digest)
        return Result("pass", "ok", sha256=digest, page_count=row["page_count"])
    except Deferred as exc:
        return Result("inconclusive", str(exc))
    except (SafeError, OSError, TypeError, ValueError, KeyError):
        return Result("inconclusive", "verify-error")
    except Exception:
        return Result("inconclusive", "verify-error")
