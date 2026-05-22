# IronMesh v0.9.4.1 — Release Notes

## Headline

A single-fix patch release on top of v0.9.4. Closes a Windows +
CPython 3.13-only race in `migrate_keys_to_master_seed` that the
v0.9.4 CI matrix surfaced as a test failure. No protocol changes,
no behaviour changes on any other platform/version, no operator
action required. v0.9.4.1 is a drop-in replacement for v0.9.4.

**Wire protocol:** `ironmesh/0.8`, additive only. Byte-identical to
v0.9.4.

## Fix

### `migrate_keys_to_master_seed` Windows race outcome

When two daemons race to migrate the same legacy keystore on
Windows + CPython 3.13, the loser's `os.replace` could occasionally
raise `PermissionError(13)` (rather than the documented "already in
master-seed format" `ValueError` that the v0.9.4 design promises).
The function now wraps both the legacy-backup copy and the final
save in `try` / `except PermissionError`; if the file is in
master-seed format at the moment of the exception, the call
surfaces the same idempotent `ValueError` the explicit pre-check
would have raised. If the file is not in master-seed format, the
original `PermissionError` re-propagates so a real permission
failure isn't masked.

Behaviour on POSIX is unchanged — `os.replace` is already atomic
there, so the new path is never taken. Behaviour on Windows
CPython 3.10 / 3.11 / 3.12 is unchanged — the race didn't surface
on those versions in CI.

CI matrix at v0.9.4.1: all 12 jobs green (3.10 / 3.11 / 3.12 / 3.13
× ubuntu + windows).

## Upgrade

```
pip install --upgrade ironmesh==0.9.4.1
```

No keystore migration, no config change, no peer-mesh coordination
required.

## Wire-format invariant

Byte-identical to v0.9.4. No wire-format change. No peer-mesh
upgrade ordering required — v0.9.4 and v0.9.4.1 daemons interoperate
identically.
