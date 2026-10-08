"""Findings depend only on metadata; no source content reaches reports."""
from pathlib import Path
import fnmatch

RULES = {"RF-DELETED", "RF-FROZEN-CHANGED", "RF-SQLITE-HEADER", "RF-INTEGRITY",
         "RF-SHRINK", "RF-ENTROPY", "RF-MASS-CHANGE", "RF-MODE", "RF-FUTURE-MTIME", "RF-DEFERRED"}


def finding(rule, entry, severity="high"):
    return {"rule": rule, "entry": entry, "severity": severity}


def compare(current, baseline, previous, targets, now_ns, mass_count=20):
    found = []
    targets = {t.get("identity", t["name"]): t for t in targets}
    by_inode = {(row["target"], row["inode"]): row for row in baseline.values()}
    baselined_targets = {row["target"] for row in baseline.values()}
    for identity, old in baseline.items():
        if old["target"] in targets and identity not in current:
            found.append(finding("RF-DELETED", identity, "critical" if old["sqlite"] else "high"))
    for identity, row in current.items():
        old = baseline.get(identity)
        is_db = row["sqlite"] or bool(old and old["sqlite"])
        if is_db and not row["sqlite_magic"]:
            found.append(finding("RF-SQLITE-HEADER", identity, "critical"))
        if row["integrity"] == "not ok":
            found.append(finding("RF-INTEGRITY", identity, "critical"))
        if row["mtime_ns"] > now_ns:
            found.append(finding("RF-FUTURE-MTIME", identity, "warn"))
        if row["class"] == "live" and is_db and (row["size"] == 0 or (old and row["size"] < old["size"] / 2)):
            found.append(finding("RF-SHRINK", identity))
        if not old:
            if row["class"] == "frozen" and row["target"] in baselined_targets:
                found.append(finding("RF-FROZEN-CHANGED", identity))
            # A renamed file can retain its inode: preserve the entropy signal
            # even when a ransomware-style rename changed the path identity.
            renamed = by_inode.get((row["target"], row["inode"]))
            if renamed and row["entropy"] > 7.5 and renamed["entropy"] < 7.0:
                found.append(finding("RF-ENTROPY", identity))
            continue
        if row["class"] == "frozen" and any(row[k] != old[k] for k in ("sha256", "size", "mtime_ns")):
            found.append(finding("RF-FROZEN-CHANGED", identity))
        if row["entropy"] > 7.5 and old["entropy"] < 7.0:
            found.append(finding("RF-ENTROPY", identity))
        if row["mode"] & ~old["mode"]:
            found.append(finding("RF-MODE", identity))
    for name, target in targets.items():
        if target["class"] != "folder":
            continue
        old = {k: v for k, v in previous.items() if v["target"] == name}
        new = {k: v for k, v in current.items() if v["target"] == name}
        if not old:
            continue
        changed = sum(k not in new or any(v[f] != new[k][f] for f in ("sha256", "size", "mtime_ns")) for k, v in old.items())
        changed += len(new.keys() - old.keys())
        old_extensions = {Path(v["path"]).suffix for v in old.values()}
        new_extensions = sum(Path(v["path"]).suffix not in old_extensions for k, v in new.items() if k not in old)
        notes = any(any(fnmatch.fnmatchcase(Path(v["path"]).name.upper(), pat) for pat in ("*DECRYPT*", "*RECOVER*", "README*.TXT")) for k, v in new.items() if k not in old)
        if changed > mass_count or changed > len(old) * .3 or new_extensions > 10 or notes:
            found.append(finding("RF-MASS-CHANGE", name, "critical"))
    return found
