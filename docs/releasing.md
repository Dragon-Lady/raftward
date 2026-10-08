# Release checks

Raft Ward releases run from `.github/workflows/publish.yml` when a GitHub release
is published. Build, private-data scan, PyPI upload, and GitHub asset attachment
are separate jobs. The PyPI and GitHub jobs verify a checksum receipt from the
scan job before using the same build artifact. Do not attach distributions by
hand.

Before publishing a new release:

1. Merge the release workflow and bump `pyproject.toml` to the new version.
2. Publish the reviewed Push Guard 0.4.1 wheel first. Set the `pypi` environment
   variable `PUSH_GUARD_041_WHEEL_SHA256` to that wheel's SHA-256 from the PyPI
   file details. The workflow rejects an unset or invalid digest and pip
   verifies the exact wheel with `--require-hashes` and `--no-deps`.
3. Keep `PUSH_GUARD_BLOCKED_TERMS` in the `pypi` environment secret, with one
   private term per line. Include the agreed personal names, private machine
   names, addresses, and phone numbers. The scan logs only the number of terms
   and requires at least three distinct terms; it never prints their values.
4. Restrict the `pypi` environment to `v*` tags and require a reviewer. Add a
   tag ruleset so only an authorized maintainer can create or update release
   tags. [GitHub's environment policy API](https://docs.github.com/en/rest/deployments/branch-policies)
   supports tag patterns; the environment must enable custom branch policies.
5. Run Push Guard against the release notes **before** making the release
   public. The publish workflow starts after that point, so it cannot prevent
   a leak in the release title or body.

Publish the release only after these settings and checks are in place. The
workflow scans every file in `dist/`; unrecognized archives fail closed. It
uploads the scanned wheel, source archive, and checksum receipt to the GitHub
release after PyPI succeeds.
