# Release evidence: Raft Ward 0.1.0

Chief cleared this source for release after the laptop and box acceptance runs.
Publication remains a separate operator action. No timer is installed or
enabled by the package.

## Implemented safety boundaries

- Per-target generic owning-app gate. A running owner or worker skips its own
  target and the report names it; unrelated targets continue. No owner allowlist.
- Unknown required local identity/same-UID descriptor visibility and every
  configured nonlocal machine defer. Other-UID executable/descriptor access is
  an explicit visibility gap; names still participate in owner gates. A same-UID
  process with kernel-owned `/proc/PID/fd`, or persistent EACCES/EPERM fd
  readlinks plus extra CapPrm/CapEff bits, is treated likewise and reported as
  `open_file_check=unverifiable`.
  No remote status attestation is accepted and no network probe is performed.
- One checkpoint per 64 KiB read chunk and SQLite progress cancellation, with
  100 ms polling measured from the end of a process sweep plus forced
  metadata/open/copy/SQLite/completion checks. A slow sweep/retry/syscall extends
  wall-clock latency. Observed owner startup discards that target's partial work
  and cleans copies.
- Only O_RDONLY source descriptors; no source SQLite connections or locking APIs.
- Disposable 0700/0600 copies; source identity/metadata verification; query-only
  immutable SQLite inspection. Presence of any SQLite sidecar defers.
- Private local state/reports; escaped HTML/Markdown; no source text retained.
  Free-text accept reasons are stored only as keyed fingerprints.
- Aggregate opt-in alert channels, five-second timeouts, 24-hour dedupe, and one
  deferral notice after 24 hours per continuous episode.

## Automated evidence

Run `python3 -m pytest -q` from this checkout. Tests cover every RF rule with
positive/negative cases, real fixture page and header corruption, 25 of 50 files
encrypted and renamed plus a note, ordinary live edits, frozen changes, accept,
all report formats, canary content non-disclosure, 0700/0600 modes, no network or
subprocesses, original hash/size/mtime/inode/mode preservation, immutable copies,
sidecar refusal, runtime cleanup on success/error/defer, source mutation mid-copy,
generic owner startup immediately after a read and during SQLite integrity work,
two database owners with one running, foreign handles, transfer processes/locks,
unknown state, PID/exec churn, other-UID permissions, same-UID bounded retries,
self-PID-only exclusion, 100 ms polling/forced boundaries, and prolonged-deferral
dedupe. Real `/proc` tests use a controlled view containing an existing root-owned
process and harmless short-lived same-UID subprocesses. They validate actual
Linux permission/churn behavior and closed fixture reads; they do not establish
full-host closure. A full-view regression checks kernel-protected same-UID
descriptors as unverifiable while retaining name matching. A 50 MiB fixture
with a 150 ms process reader checks bounded completion. SIGTERM and stale-copy
tests cover runtime cleanup. Exact test count is in the builder's
delivery report; do not infer real-machine acceptance from fixture passes.

## Outstanding acceptance and deliberate limits

1. **Remote closure is not implemented.** Any configured remote machine defers
   the entire run. Cross-machine operation requires an independently reviewed
   authenticated current-state design, not a cached status flag.
2. **WAL content validation is not implemented.** Real WAL fixtures prove safe
   deferral and unchanged originals, not integrity of uncheckpointed WAL data.
   WAL/SHM/journal files are never removed or modified.
3. **Polling is not an interlock.** Process startup can race a syscall or occur
   between checkpoints. There is no claim of instantaneous zero-race protection.
   Users must keep owning applications closed for the full run.
4. Chief reported that the laptop run checked a scratch SQLite database and
   skipped a database owned by a running `bash` process with zero syscalls to
   that skipped target. `systemd --user` and `sd-pam` were reported as
   descriptor-unverifiable. Ordinary same-UID descriptor denial still deferred.
   Chief reported 138/138 box tests passing and SIGINT exit 130 with clean
   cancellation. This acceptance applies to the tested local configuration;
   it does not establish closure on another machine.
5. Accept reasons are fingerprinted rather than persisted as raw text. This is a
   deliberate privacy narrowing of the initial scope.
6. No network alert was sent during fixture tests. Source commits, package
   hashes, and publication status are verified separately in the release record.
7. Hard-kill/power-loss cleanup cannot be guaranteed. SIGTERM/SIGINT invoke
   cleanup; a startup sweep removes stale `run-*` directories in the private
   runtime directory. SIGINT during SQLite integrity work exits 130 without an
   integrity finding; a hard kill can leave a copy until that next run.
8. The no-source-write promise covers bytes, names, size, mtime, inode, and mode;
   filesystems may update atime if `O_NOATIME` is not permitted and O_RDONLY is
   used. This fallback is documented and never changes file permissions.

9. Other-UID descriptor holders are not observable. Readable comm/cmdline still
   gates each target's configured owner and all transfers, but cannot prove all
   other-UID handles are closed. Kernel-protected same-UID fd directories and
   proven extra-capability readlink denials share that visibility gap. A full
   host process view is required; hidepid or an
   incomplete PID namespace cannot establish closure. Other same-UID fd failures
   remain fatal.
10. Permanent rclone mounts and rsync daemons deliberately defer all target work.
    The delayed notice explains this; no subcommand/mount exemption is implemented.

This release does not satisfy cross-machine closure or live-WAL validation.
No installed scheduler should run it against those targets.
