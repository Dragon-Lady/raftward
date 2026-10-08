# Raft Ward

Raft Ward checks the integrity of closed SQLite databases, frozen exports, and
backup folders. It detects missing files, corruption, suspicious shrinkage,
permission changes, and patterns consistent with bulk encryption or renaming.
It does not repair, restore, quarantine, or modify the files it watches.

Version 0.1.0 is free software under Apache-2.0, for Linux with Python 3.10
or newer. Its only runtime dependency is
`tomli` on Python 3.10.

## Posture

- Local, read-only target access; no telemetry. No network or child processes by
  default. Configured alert delivery is the only network feature.
- Every watched target has configured owning applications. A running app or
  background worker skips its own target, with its name and reason in the report.
  Other targets continue. No metadata, hashing, or integrity work starts for a
  target whose owner is already observed running.
- Unknown process visibility or any configured nonlocal machine also defers the
  entire run. A stale local status file never counts as remote closure.
- Owner matching is generic and case insensitive across Linux `/proc` process
  names, executable paths, and command lines. Cursor and Codex are defaults, not
  special cases. There is no owning-process allowlist.
- Targets are opened only with read-only descriptors, no locks. SQLite is never
  connected to an original. Source symlinks, unsupported files, foreign-owned
  paths, a visible same-UID foreign target/sidecar descriptor, transfer locks, and running
  configured transfer programs defer the run.
- Writes are restricted to private application state, an explicit new report
  file, and disposable private SQLite copies under `$XDG_RUNTIME_DIR/raftward`.
  Report/state/runtime locations cannot overlap configured target trees.
- Persistent state contains local paths, keyed identifiers, file metadata,
  SHA-256 file digests, entropy measurements, findings, and timestamps. It contains
  no database rows, message text, file excerpts, full process arguments, or
  conversation data. SQLite copies contain source bytes briefly and are deleted
  in cleanup on success, deferral, interruption, or exception. On the next run,
  stale private copies are removed from the runtime directory.

Keep all involved applications and workers closed for the full run. A polling
guard cannot establish an atomic interlock with an unrelated application. Raft
Ward reaches one checkpoint after each 64 KiB source chunk, throughout
directory walks, and every 100 SQLite virtual-machine instructions. Repeated
process enumeration is throttled to a 100 ms interval measured from the end of
the previous enumeration at these checkpoints.
Mandatory checks bypass that interval before target metadata/open, initial source
copying, private-copy creation, SQLite connection/integrity work, and completion.
A slow process enumeration, bounded retry, or blocked filesystem call can extend
the wall-clock delay; this is not a real-time deadline. Once a running owner is
observed, that target's result is discarded while other targets continue; cleanup
closes descriptors and removes its private copy. An app can start between a check
and a syscall or entirely between
checks. No zero-race protection is claimed.

## Install and configure

From a reviewed checkout:

```sh
python3 -m pip install .
raftward --help
```

Copy and edit `examples/config.toml` into
`$XDG_CONFIG_HOME/raftward/config.toml` (default
`~/.config/raftward/config.toml`). Create that configuration with mode **0600**.
There are no automatically scanned targets. Every target has a unique simple
name, `path`, `class`, and nonempty `owners` list. If `owners` is omitted it
defaults to all configured owners. The default owners are `cursor` and `codex`.

```toml
machines = ["local"]
alert_channels = ["stdout"]

[owners]
notes = ["notes-app", "notes-worker"]

[[targets]]
name = "notes-export"
path = "~/backups/notes.sqlite"
class = "frozen"
sqlite = true
owners = ["notes"]
```

`live` tolerates ordinary hash and mtime changes. `frozen` flags changes in hash,
size, or mtime. `folder` recursively checks mixed files and evaluates bulk changes
since the last completed run. `sqlite = true` identifies an expected database
even if its header is already damaged; it defaults true for `live`. Recognizable
SQLite files found in any class also get integrity checks. Prefer explicit
`sqlite = true` for frozen database exports.

File and directory globs support `*`, `?`, and bracket patterns. Recursive `**`
globs defer; use a `folder` target for recursive scanning. Symlinks are never
followed. Defaults are 10,000 files and a 20-file mass-change threshold. A folder
containing other users' files defers rather than silently skipping them. Broad
owner substrings may yield conservative false positives.

**Multi-machine operation:** list every involved machine in `machines`, including
`local`. v0.1 cannot prove current remote app state and therefore always defers if
this list includes another machine. There is no SSH, remote helper, status-file
override, or network probe. Do not omit an involved machine to get around this
gate. Coordinated cross-machine inspection remains a review/release gap.

## Commands

```sh
raftward guard
raftward baseline
raftward check --quick --max-gb 2
raftward check --target notes-export --format html --output /tmp/raft-report.html
raftward accept notes-export --reason "verified closed export"
raftward baseline export --format json
raftward status
raftward report --since 7d
raftward report --since 24h --send
raftward targets list
raftward targets add packets ~/backups/packets --class folder --owner notes
raftward targets remove packets
raftward print-timer --interval 30m
```

All commands accept `--format text|json|md|html` and `--output NEW_FILE`.
Global `--config FILE` and `--state DIR` options precede the command. Report
destinations must already have a parent directory; existing files are never
overwritten. Text output is a readable metadata record; JSON is structured data.
Markdown and HTML escape all interpolated values and load no external assets.

`guard` inspects process state and configured transfer-lock metadata only; it does
not stat or open watched targets. `status`, `report`, `targets list`, and `baseline
export` read stored application metadata only and do not scan sources. A guard
result is valid at that checkpoint, not a promise about a later check.

`baseline` captures all targets or `--target NAME`; replacing an existing baseline
requires `--force`. `accept TARGET` re-baselines one reviewed change. Neither will
bless missing targets, a lost expected SQLite header, failed integrity, or future
mtime. An accept records time, target, and an HMAC fingerprint of the optional
reason; it intentionally does **not** retain free text, which might contain
credentials or personal conversation. `targets add/remove` writes a private
complete target list in state that takes precedence over the TOML target list;
owner definitions still come from TOML.

Checks use `nice(10)` when allowed. `--max-gb` limits source bytes for the entire
run; exceeding it defers rather than recording a partial success. The runtime
directory must be available in `XDG_RUNTIME_DIR`. `--quick` requests
`PRAGMA quick_check`; full `integrity_check` is the default.

Exit codes: **0** no findings/success, **1** findings or rejected unsafe baseline,
**2** usage/runtime/alert-delivery error, **3** deferred or partial check/guard/status. A report
returns 1 when the requested history contains findings. Timer unit text is printed
as report data only. Review the `ExecStart` executable path before installing
units yourself; Raft Ward never installs, enables, or starts timers.

## SQLite and transfer boundaries

For a closed source without sidecars, Raft Ward copies bytes through bounded
read-only reads into a unique 0700 directory. The copy is created 0600 before any
bytes are written. Source device/inode, size, mtime, ctime, and mode are checked
again. The copy is opened with `mode=ro&immutable=1`, `query_only=ON`,
`trusted_schema=OFF`, and `temp_store=MEMORY`. Only `ok`/`not ok` and page count
are retained from SQLite; diagnostic strings may reveal content and are discarded.

**Any `-wal`, `-shm`, or `-journal` beside a SQLite target defers the entire run.**
Raft Ward never assumes immutable mode validates uncheckpointed WAL contents. It
does not checkpoint or remove sidecars. A closed WAL-mode main database without
sidecars can be checked as a main-file snapshot. WAL reconstruction and live WAL
integrity validation are explicitly unsupported.

Configured `transfer_commands` default to `rclone` and `rsync`. Any matching
process stops the entire run even when its arguments do not identify a target.
This includes permanent `rclone mount` processes and rsync daemons: they can defer
every run indefinitely. The 24-hour deferral notice names this conservative
transfer policy. Subcommand/target attribution has not been proven safe and no
mount or daemon exemption is applied. `transfer_dirs` stops work if a process
command references a configured directory; `transfer_locks` and singular
`transfer_lock` are supported. No process is stopped or signaled.

Raft Ward requires a full host `/proc` view. A restricted `hidepid` mount defers;
a PID namespace containing only a subset of the host is not proof that other
owners are closed. Owner/worker and transfer matching uses `comm` plus `cmdline`
for every visible process, with `exe` as supplementary identity when readable.
Only Raft Ward's own PID is excluded; its parent, sibling processes, and workers
are still checked. Same-UID identity/descriptor permission failures get three
50 ms rereads. A persistently unavailable `exe` may be omitted when identity
remains readable. A same-UID process whose `/proc/PID/fd` is kernel-owned, such
as a non-dumpable user service, participates in name matching while its open-file
check is reported as `unverifiable`. The same applies when fd entries remain
listable but their readlinks return EACCES/EPERM after retries and the process's
CapPrm or CapEff contains capabilities absent from our own. Readable fd links
still participate in target-handle checks. Other unreadable same-UID identity
or descriptors still defer.
`process-descriptor-state-unknown` distinguishes descriptor visibility failure.

Other-UID `exe` and descriptor access is normally restricted by Linux. Raft Ward
matches those processes using readable `comm`/`cmdline`; at least one identity
field must be readable. It does not inspect other-UID descriptors and cannot prove
that another user (including root) has no target file open. This is an explicit
visibility gap, not a closed-state claim. Transient ENOENT/ESRCH means a vanished
process/descriptor; readable owner names are retained when only `exe` disappears.
PID reuse/UID changes trigger a reread. No owner allowlist or privilege request is
used to make an unknown state pass.

## Findings

| Rule | Condition |
| --- | --- |
| `RF-DELETED` | Missing configured target or previously baselined file |
| `RF-FROZEN-CHANGED` | Frozen file hash, size, or mtime changed |
| `RF-SQLITE-HEADER` | Expected SQLite magic lost |
| `RF-INTEGRITY` | SQLite copy check did not return `ok` |
| `RF-SHRINK` | Live database empty or below 50% of its baseline size |
| `RF-ENTROPY` | First 4 KiB moved from below 7.0 to above 7.5 bits/byte |
| `RF-MASS-CHANGE` | Folder changes exceed 20 files or 30%, over 10 new-extension files appear, or a new decrypt/recover/readme-text note appears |
| `RF-MODE` | Any permission bits loosened relative to baseline |
| `RF-FUTURE-MTIME` | Mtime ahead of the check clock |
| `RF-DEFERRED` | More than 24 hours continuously deferred; one informational alert per episode |

Renames that retain an inode retain the entropy comparison. A replacement written
to a new inode/path cannot be reliably associated with the old file; deletion,
extension, and mass-change findings still apply. These are evidence signals, not
a malware diagnosis. Entropy is estimated from a sample, not the whole file.

## State, privacy, and alerts

State is under `$XDG_STATE_HOME/raftward` (default `~/.local/state/raftward`), mode
0700. Files are created 0600 with `os.open`; no post-write chmod is used. Unsafe
existing state permissions or symlinked parents are refused, not repaired.

- `fp.key`: 32 random bytes used for HMAC-SHA256 identifiers (`fp:` plus 16 hex
  characters). A missing key beside an existing baseline is an error.
- `baseline.json`, `previous.json`, `last.json`: metadata and findings.
- `history.jsonl`: at most 30 days and 4 MiB of recent metadata (older rows trimmed).
- `accepts.jsonl`: review records with reason fingerprints, at most 4 MiB.
- `targets.json`: optional CLI-managed targets; `deferred.json`: deferral episode;
  `alerts.json`: hashed delivery receipts with a 24-hour dedupe period.

Paths appear only locally. Recognized token-shaped substrings in local metadata
are HMAC-redacted. Because arbitrary filenames and operator-supplied configuration
are not universally recognizable as secrets, keep credentials out of target
names and paths. File contents are never rendered or scanned for display.

Critical findings alert during `check`. Other findings are available in reports;
`report --send` explicitly delivers their aggregate summary. `alert_channels`
accepts `stdout`, `slack`, `ntfy`, or `email`; an empty list means stdout. Network
delivery is opt-in by configuring a non-stdout channel. Payloads contain rule IDs,
counts, and severity only, and end with
"run `raftward report` locally for details". They contain no hostname, paths,
process arguments, or file content. Delivery is deduped for 24 hours and uses a
five-second timeout. Redirects are not followed.

Use environment-variable **names**, never inline credentials:
`alert_slack_webhook_env`, `alert_ntfy_token_env`, `alert_smtp_password_env`.
Other channel keys are `alert_ntfy_topic`, `alert_smtp_host`, `alert_smtp_port`,
`alert_smtp_security` (`starttls`, `ssl`, or loopback-only `none`),
`alert_smtp_username`, `alert_smtp_from`, and `alert_email`. HTTPS is required
except on loopback; SMTP encryption is required off loopback. Errors never echo
remote credential-bearing URLs.

## Development and review

```sh
python3 -m pytest -q
```

Tests use a temporary HOME, fixture databases, and injected process listings.
They do not inspect real application data. No timer is installed. See
`REVIEW.md` for the independent acceptance report and remaining limits.
