"""Configuration is data. No process command or remote hook is executed."""
import os
from pathlib import Path
import re
import stat
try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib

from .safety import SafeError, absolute, bounded_read

DEFAULT_OWNERS = {"cursor": ["cursor"], "codex": ["codex"]}
NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")


def locations():
    home = absolute(Path.home())
    cfg = absolute(os.environ.get("XDG_CONFIG_HOME", home / ".config")) / "raftward/config.toml"
    state = absolute(os.environ.get("XDG_STATE_HOME", home / ".local/state")) / "raftward"
    return cfg, state


def strings(value):
    return isinstance(value, list) and all(isinstance(v, str) and v and "\x00" not in v for v in value)


def validate(cfg):
    if not isinstance(cfg, dict):
        raise SafeError("configuration must be a table")
    cfg = dict(cfg)
    owners = cfg.setdefault("owners", DEFAULT_OWNERS.copy())
    if not isinstance(owners, dict) or not owners or any(not NAME.fullmatch(k) or not strings(v) or not v for k, v in owners.items()):
        raise SafeError("owners must map names to nonempty process-pattern lists")
    cfg.setdefault("machines", ["local"])
    if not strings(cfg["machines"]) or not cfg["machines"] or "local" not in cfg["machines"]:
        raise SafeError("machines must include local and all involved machines")
    targets = cfg.setdefault("targets", [])
    if not isinstance(targets, list):
        raise SafeError("targets must be an array of tables")
    names = set()
    result = []
    for original in targets:
        if not isinstance(original, dict):
            raise SafeError("invalid target table")
        t = dict(original)
        name, path = t.get("name"), t.get("path")
        if not isinstance(name, str) or not NAME.fullmatch(name) or name in names:
            raise SafeError("target names must be unique simple identifiers")
        names.add(name)
        if not isinstance(path, str) or not path or "\x00" in path:
            raise SafeError("target path is required")
        t["path"] = str(absolute(path))
        if t.get("class") not in {"live", "frozen", "folder"}:
            raise SafeError("target class must be live, frozen, or folder")
        t.setdefault("owners", list(owners))
        if not strings(t["owners"]) or not t["owners"] or any(v not in owners for v in t["owners"]):
            raise SafeError("every target requires configured owners")
        t.setdefault("sqlite", t["class"] == "live")
        if not isinstance(t["sqlite"], bool):
            raise SafeError("sqlite must be a boolean")
        result.append(t)
    cfg["targets"] = result
    for field in ("transfer_commands", "transfer_dirs", "transfer_locks", "alert_channels"):
        if field in cfg and not strings(cfg[field]):
            raise SafeError("invalid configuration list")
    if "transfer_lock" in cfg:
        if not isinstance(cfg["transfer_lock"], str):
            raise SafeError("invalid transfer lock")
        cfg["transfer_locks"] = cfg.get("transfer_locks", []) + [cfg["transfer_lock"]]
        cfg.pop("transfer_lock")
    cfg.setdefault("transfer_commands", ["rclone", "rsync"])
    cfg.setdefault("transfer_dirs", [])
    cfg.setdefault("transfer_locks", [])
    for field, default in (("mass_count", 20), ("max_files", 10000)):
        cfg.setdefault(field, default)
        if type(cfg[field]) is not int or cfg[field] < 1:
            raise SafeError("invalid positive integer limit")
    if "alert_slack_webhook" in cfg:
        raise SafeError("use alert_slack_webhook_env; inline webhooks are not accepted")
    if any(c not in {"stdout", "slack", "ntfy", "email"} for c in cfg.get("alert_channels", [])):
        raise SafeError("invalid alert channel")
    return cfg


def load(path):
    try:
        raw, info, _ = bounded_read(path)
    except FileNotFoundError:
        return validate({})
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise SafeError("config must be owned by this user, single-linked, and mode 0600")
    try:
        cfg = tomllib.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise SafeError("invalid TOML configuration") from None
    return validate(cfg)
