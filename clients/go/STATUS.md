# IronMesh Go client — status

**Reference implementation. Not a production client.**

This directory contains a minimal Go client whose only purpose is to
prove the IronMesh wire protocol is implementable outside Python. It is
a reference, not a supported product, and must not be deployed as
production infrastructure.

## Protocol-version gap (read before connecting)

This client advertises **`ironmesh/0.6`** in its handshake
(`clients/go/ironmesh/handshake.go`). The core protocol floor is
**`ironmesh/0.9`** — the daemon announces `ironmesh/0.9`. Against a mesh
running the default floor of 0.9, or against any node in strict mode,
this client is **refused at the handshake** until its advertised
version is bumped. It will complete a handshake only against a daemon
explicitly configured to accept the older version.

## Build / CI status

- The Go client is **currently outside the CI matrix** — it is not
  built or tested by continuous integration.
- It **does not build cleanly locally** at present.
- Any successful build should be treated as unverified.

## Roadmap

The version bump to the current protocol floor and inclusion in the CI
matrix are **scheduled for 0.9.6 / 0.10.0**. Until then, use this code
to read the protocol, not to run it in anything you depend on.

## License

MIT — same as the rest of IronMesh.
