# IronMesh TypeScript client — status

**Reference implementation. Not a production client.**

The TypeScript client in this directory is a reference implementation of
the IronMesh wire protocol for Node.js. It is useful for reading the
protocol and for experimentation, but it is **not** a supported,
production-ready client and must not be treated as production
infrastructure.

## Protocol-version gap (read before connecting)

This client advertises **`ironmesh/0.6`** in its handshake
(`PROTOCOL_VERSION` in `src/handshake.ts`). The core protocol floor is
**`ironmesh/0.9`** — the daemon announces `ironmesh/0.9`. Against a mesh
running the default floor of 0.9, or against any node in strict mode,
this client is **refused at the handshake** until its advertised
version is bumped. It will complete a handshake only against a daemon
explicitly configured to accept the older version.

> Note: `README.md` in this directory describes compatibility with the
> v0.9.x daemon **release line**. That is separate from the advertised
> **wire** version. The advertised `ironmesh/0.6` sits below the 0.9
> floor, and it is the wire version — not the release line — that
> governs whether a handshake is accepted.

## CI status

The TypeScript client is not yet part of the CI matrix.

## Roadmap

The version bump to the current protocol floor and inclusion in the CI
matrix are **scheduled for 0.9.6 / 0.10.0**.

## License

MIT — same as the rest of IronMesh.
