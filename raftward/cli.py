"""CLI operations modify only private Raft Ward state and explicit reports."""
import argparse
from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import re
import signal
import sys
import threading
import time

from . import __version__
from . import alerts
from .audit import compare, finding
from .config import load, locations, validate
from .guard import Deferred, Guard, overlaps
from .reports import render
from .safety import SafeError, Store, Redactor, absolute, fingerprint, write_private
from .scanner import Scanner

FORMATS = ("text", "json", "md", "html")
RETENTION = 30 * 86400


class _Interrupted(KeyboardInterrupt):
    def __init__(self, signum):
        self.signum = signum


@contextmanager
def _interrupt_cleanup():
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    prior = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}
    def stop(signum, _frame):
        raise _Interrupted(signum)
    try:
        for number in prior:
            signal.signal(number, stop)
        yield
    finally:
        for number, handler in prior.items():
            signal.signal(number, handler)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise SafeError("invalid command arguments; use --help")


def parser():
    p = Parser(prog="raftward", description="Offline integrity checks with per-target owning-app guards")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--config")
    p.add_argument("--state")
    commands = p.add_subparsers(dest="command", required=True)

    def output(item):
        item.add_argument("--format", choices=FORMATS, default="text")
        item.add_argument("--output")
        return item

    def scanning(item):
        output(item)
        item.add_argument("--target")
        item.add_argument("--quick", action="store_true")
        item.add_argument("--max-gb", type=float)
        return item

    scanning(commands.add_parser("check"))
    baseline = scanning(commands.add_parser("baseline"))
    baseline.add_argument("action", nargs="?", choices=["export"])
    baseline.add_argument("--force", action="store_true")
    accept = scanning(commands.add_parser("accept"))
    accept.add_argument("name")
    accept.add_argument("--reason", default="")
    output(commands.add_parser("status"))
    output(commands.add_parser("guard"))
    report = output(commands.add_parser("report"))
    report.add_argument("--since", default="7d")
    report.add_argument("--send", action="store_true")
    timer = output(commands.add_parser("print-timer"))
    timer.add_argument("--interval", default="30m")
    target = output(commands.add_parser("targets"))
    target.add_argument("action", choices=["add", "remove", "list"])
    target.add_argument("name", nargs="?")
    target.add_argument("path", nargs="?")
    target.add_argument("--class", dest="klass", choices=["live", "frozen", "folder"], default="frozen")
    target.add_argument("--owner", action="append")
    target.add_argument("--sqlite", action="store_true", default=None)
    return p


def seconds(text):
    match = re.fullmatch(r"([1-9][0-9]{0,4})([smhd])", text)
    if not match:
        raise SafeError("duration must be a positive number followed by s, m, h, or d")
    return int(match[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]


def ensure_destination(path, cfg):
    dest = absolute(path)
    for target in cfg["targets"]:
        # Globs' fixed prefix conservatively protects their containing tree.
        pattern = target["path"]
        prefix = re.split(r"[*?[]", pattern, maxsplit=1)[0]
        root = absolute(prefix if prefix.endswith("/") else str(Path(prefix).parent)) if prefix != pattern else absolute(pattern)
        if overlaps(str(dest), target) or (prefix != pattern and (dest == root or dest.is_relative_to(root))):
            raise SafeError("output/state/runtime destination overlaps a watched target")
        if absolute(pattern).is_relative_to(dest):
            raise SafeError("watched target overlaps output/state/runtime destination")


def history(store):
    try:
        raw = store.read("history.jsonl", raw=True)
    except FileNotFoundError:
        return []
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def save_history(store, result, now):
    rows = [row for row in history(store) if row.get("time", 0) >= now - RETENTION]
    rows.append(result)
    data = "".join(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n" for row in rows)
    # Bounded metadata only; trim oldest rows, preserving the most recent run.
    while len(data.encode()) > 4 * 1024 * 1024 and len(rows) > 1:
        rows.pop(0)
        data = "".join(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n" for row in rows)
    if len(data.encode()) > 4 * 1024 * 1024:
        raise SafeError("report metadata exceeds state budget")
    write_private(store.path / "history.jsonl", data, replace=True)


def runtime_path():
    value = os.environ.get("XDG_RUNTIME_DIR")
    if not value:
        raise Deferred("xdg-runtime-dir-required")
    return absolute(value) / "raftward"


def record_deferred(store, cfg, reason, now, redactor, skipped=None, open_file_check=None):
    old = store.read("deferred.json", {})
    first = old.get("first", now)
    notified = bool(old.get("notified", False))
    result = {"time": now, "status": "deferred", "reason": reason,
              "targets": [t["name"] for t in cfg["targets"]], "findings": [],
              "skipped": skipped or []}
    if open_file_check is not None:
        result["open_file_check"] = open_file_check
    if now - first >= 86400 and not notified:
        event = finding("RF-DEFERRED", fingerprint(store.key, str(first)), "info")
        event["reason"] = reason
        result["alerts"] = alerts.deliver(cfg, store, [event], [], now)
        notified = not result["alerts"]["failed"]
    store.save("deferred.json", {"first": first, "notified": notified})
    result = redactor.clean(result)
    store.save("last.json", result)
    save_history(store, result, now)
    return result, 3


def execute(args, cfg, store, redactor, guard_factory=Guard, now=None):
    now = time.time() if now is None else now
    command = args.command
    if command == "targets":
        if args.action == "list":
            return {"targets": cfg["targets"]}, 0
        if args.action == "add":
            if not args.name or not args.path:
                raise SafeError("targets add requires NAME and PATH")
            if redactor.clean(args.path) != args.path or redactor.clean(args.name) != args.name:
                raise SafeError("secret-shaped target paths are not accepted by targets add")
            new = {"name": args.name, "path": args.path, "class": args.klass}
            if args.owner:
                new["owners"] = args.owner
            if args.sqlite is not None:
                new["sqlite"] = args.sqlite
            cfg = validate(dict(cfg, targets=cfg["targets"] + [new]))
        else:
            if not args.name or args.name not in {t["name"] for t in cfg["targets"]}:
                raise SafeError("unknown target")
            cfg = validate(dict(cfg, targets=[t for t in cfg["targets"] if t["name"] != args.name]))
        if any(redactor.clean(t["path"]) != t["path"] or redactor.clean(t["name"]) != t["name"] for t in cfg["targets"]):
            raise SafeError("refused to persist secret-shaped managed target metadata")
        ensure_destination(store.path, cfg)
        store.save("targets.json", cfg["targets"])
        return {"targets": cfg["targets"]}, 0
    if command == "print-timer":
        interval = seconds(args.interval)
        # Unit text is data only; no install/enable/start calls exist.
        return {"raftward.service": "[Unit]\nDescription=Raft Ward guarded integrity check\n[Service]\nType=oneshot\nExecStart=%h/.local/bin/raftward check\nNice=10\nSuccessExitStatus=1 3\nUMask=0077\n",
                "raftward.timer": f"[Unit]\nDescription=Raft Ward periodic check\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec={interval}s\nPersistent=true\n[Install]\nWantedBy=timers.target\n"}, 0
    if command == "status":
        last = store.read("last.json", {"status": "never-checked", "targets": [t["name"] for t in cfg["targets"]]})
        return last, 3 if last["status"] in {"deferred", "partial"} else int(bool(last.get("findings")))
    if command == "report":
        rows = [row for row in history(store) if row["time"] >= now - seconds(args.since)]
        report = {"runs": rows, "count": len(rows)}
        if args.send:
            report["alerts"] = alerts.deliver(cfg, store, [f for row in rows for f in row.get("findings", [])], [], now)
        return report, 2 if report.get("alerts", {}).get("failed") else int(any(row.get("findings") for row in rows))
    baseline = store.read("baseline.json", {"entries": {}})
    if command == "baseline" and args.action == "export":
        return baseline, 0
    guard = guard_factory(cfg)
    try:
        if command == "guard":
            skipped = []
            if not cfg["targets"]:
                guard.check(force=True, targets=[])
            for target in cfg["targets"]:
                try:
                    guard.check(force=True, targets=[target])
                except Deferred as exc:
                    if str(exc) != "owning-app-running":
                        raise
                    skipped.append({"name": target["name"], "reason": "owning-app-running"})
            return {"status": "partial" if skipped else "clear-at-checkpoint",
                    "targets": [t["name"] for t in cfg["targets"]], "skipped": skipped,
                    "open_file_check": guard.open_file_check}, 3 if skipped else 0
        if not cfg["targets"]:
            raise SafeError("configure at least one watched target")
        selected = getattr(args, "name", None) if command == "accept" else args.target
        targets = [t for t in cfg["targets"] if not selected or t["name"] == selected]
        if not targets:
            raise SafeError("unknown target")
        targets = [dict(t, identity=fingerprint(store.key, "target\0" + t["name"])) for t in targets]
        if command == "baseline" and baseline["entries"] and not args.force:
            raise SafeError("baseline already exists; use --force or accept TARGET")
        max_gb = args.max_gb
        if max_gb is not None and (not math.isfinite(max_gb) or max_gb <= 0):
            raise SafeError("max-gb must be a positive finite number")
        runtime = runtime_path()
        ensure_destination(runtime, cfg)
        try:
            os.nice(10)
        except OSError:
            pass
        scanner = Scanner(cfg, guard, store.key, runtime, None if max_gb is None else int(max_gb * 1024**3), args.quick)
        current, missing = scanner.scan(targets, baseline["entries"])
        skipped_names = {item["name"] for item in scanner.skipped}
        scanned_targets = [target for target in targets if target["name"] not in skipped_names]
        if not scanned_targets:
            return record_deferred(store, cfg, "owning-app-running", now, redactor,
                                   scanner.skipped, guard.open_file_check)
        previous = store.read("previous.json", {"entries": {}})["entries"]
        findings = compare(current, baseline["entries"], previous or baseline["entries"], scanned_targets, int(now * 1e9), cfg["mass_count"])
        for name in missing:
            identity = fingerprint(store.key, "target\0" + name)
            if not any(old["target"] == identity for old in baseline["entries"].values()):
                findings.append(finding("RF-DELETED", identity, "critical"))
        current = redactor.clean(current)
        result = {"time": now, "status": "checked", "targets": [t["name"] for t in targets],
                  "entries": current, "findings": findings, "bytes_read": scanner.bytes,
                  "integrity_check": "quick" if args.quick else "full",
                  "skipped": scanner.skipped, "open_file_check": guard.open_file_check}
        if command in {"baseline", "accept"}:
            # Never bless corruption, missing data, or observed suspicious changes
            # by accident. Explicit accept clears difference-only findings, but
            # invalid SQLite cannot become a known-good baseline.
            intrinsic = {"RF-SQLITE-HEADER", "RF-INTEGRITY", "RF-FUTURE-MTIME"}
            blocked = [f for f in findings if f["rule"] in intrinsic or (missing and f["rule"] == "RF-DELETED")]
            if blocked:
                result["status"] = "baseline-refused"
            else:
                names = {t["identity"] for t in scanned_targets}
                entries = {k: v for k, v in baseline["entries"].items() if v["target"] not in names}
                entries.update(current)
                store.save("baseline.json", {"time": now, "entries": entries})
                result["findings"] = []
                result["status"] = "accepted" if command == "accept" else "baselined"
                if command == "accept":
                    try:
                        records = store.read("accepts.jsonl", raw=True).decode()
                    except FileNotFoundError:
                        records = ""
                    # Free-text reasons could contain pasted secrets or conversation
                    # content. Persist only their keyed fingerprint and presence.
                    entry = {"target": selected, "time": now, "reason_fp": fingerprint(store.key, args.reason) if args.reason else None}
                    records += json.dumps(redactor.clean(entry), sort_keys=True) + "\n"
                    if len(records.encode()) > 4 * 1024 * 1024:
                        raise SafeError("accept history budget exceeded")
                    write_private(store.path / "accepts.jsonl", records, replace=True)
        old_previous = {k: v for k, v in previous.items() if v["target"] not in {t["identity"] for t in scanned_targets}}
        old_previous.update(current)
        store.save("previous.json", {"time": now, "entries": old_previous})
        store.save("deferred.json", {})
        critical = [f for f in result["findings"] if f["severity"] == "critical"]
        if critical:
            result["alerts"] = alerts.deliver(cfg, store, critical, [], now)
        result = redactor.clean(result)
        if scanner.skipped and result["status"] not in {"baseline-refused"}:
            result["status"] = "partial"
        store.save("last.json", result)
        save_history(store, result, now)
        return result, 2 if result.get("alerts", {}).get("failed") else 3 if scanner.skipped else int(bool(result["findings"]))
    except Deferred as exc:
        if command == "guard":
            return {"status": "deferred", "reason": str(exc), "targets": [t["name"] for t in cfg["targets"]]}, 3
        return record_deferred(store, cfg, str(exc), now, redactor,
                               open_file_check=guard.open_file_check)


def main(argv=None):
    try:
        args = parser().parse_args(argv)
        config_path, state_path = locations()
        cfg = load(absolute(args.config) if args.config else config_path)
        state_path = absolute(args.state) if args.state else state_path
        ensure_destination(state_path, cfg)
        store = Store(state_path)
        managed = store.read("targets.json")
        if managed is not None:
            cfg = validate(dict(cfg, targets=managed))
            ensure_destination(state_path, cfg)
        if getattr(args, "output", None):
            ensure_destination(args.output, cfg)
        redactor = Redactor(store.key)
        # Known token shapes in paths are redacted, but "path" is not a PAT
        # credential field. Passing the complete config to a generic credential
        # discovery routine would fingerprint every ordinary path.
        for target in cfg["targets"]:
            redactor.discover([target["path"], target["name"]])
        for field, value in cfg.items():
            if field.startswith("alert_") and field.endswith("_env") and isinstance(value, str):
                alert_value = os.environ.get(value)
                if alert_value:
                    redactor.add(alert_value)
        with _interrupt_cleanup():
            data, code = execute(args, cfg, store, redactor)
        # Unit templates contain only fixed literals and a parsed integer;
        # preserve their actual line breaks rather than sanitizing them as data.
        output = render(data if args.command == "print-timer" else redactor.clean(data), args.format)
        if args.output:
            write_private(absolute(args.output), output)
        else:
            sys.stdout.write(output)
        return code
    except _Interrupted as exc:
        sys.stderr.write("raftward: interrupted; private copy cleanup attempted\n")
        return 128 + exc.signum
    except KeyboardInterrupt:
        sys.stderr.write("raftward: interrupted; private copy cleanup attempted\n")
        return 130
    except SafeError as exc:
        sys.stderr.write("raftward: " + str(exc) + "\n")
        return 2
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        # Never echo paths, TOML excerpts, arguments, or exception strings.
        sys.stderr.write("raftward: operation failed; check local configuration and private state\n")
        return 2
