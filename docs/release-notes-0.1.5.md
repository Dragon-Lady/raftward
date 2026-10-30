# Raft Ward 0.1.5 release notes

This release adds one opt-in, fixed owner exemption. With
`owner_exempt = ["cursor-agent-worker"]` in the config, or
`gate(..., owner_exempt=["cursor-agent-worker"])` in the Python API, Cursor's
detached background agent worker (`cursor-agent ... worker start`) no longer
counts as an owner of Cursor targets. The Cursor editor and every other
`cursor-agent` command still do.

An exempt worker is still checked for open target descriptors and transfer
activity, and its arguments are never recorded. `owner_exempt` accepts only
known kinds; any other value is a configuration error.

The default is off, so existing configs and API callers behave exactly as in
0.1.4.
