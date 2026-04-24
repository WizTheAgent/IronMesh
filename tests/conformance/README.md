# IronMesh conformance test suite

This directory holds **language-agnostic golden vectors** that any
IronMesh implementation can use to prove spec compliance. The
Python reference implementation runs these via
`tests/test_conformance_vectors.py`; a Go / Rust / Swift port can
load the same JSON files and compare against its own
serialisation.

The suite is the basis of the v1.0 stability promise: an
implementation that passes every vector here interoperates with
the reference implementation by construction.

## Vector file format

Each vector is one JSON file in `vectors/` with this shape:

```json
{
  "name": "frame.HELLO.minimal",
  "description": "HELLO frame with minimum required fields, unsigned, unencrypted.",
  "spec_section": "PROTOCOL_SPEC.md §3",
  "version": "ironmesh/0.8",
  "input": { ... },
  "expected_bytes_hex": "e7f604... ",
  "expected_decoded": { ... }
}
```

* `name` is `<category>.<message-type>.<scenario>` — categories are
  `frame`, `handshake`, `announce`, `routing`, `capability`.
* `input` is the high-level decoded form (a structure the
  implementation under test can construct).
* `expected_bytes_hex` is the canonical wire encoding the
  implementation must produce.
* `expected_decoded` is what the implementation must produce when
  given `expected_bytes_hex` as input.

A vector is **directional**: `input → bytes` and `bytes → decoded`
must both pass. This catches asymmetric serialisation bugs.

## Vector categories

| Category | Coverage |
| --- | --- |
| `frame.*` | Binary wire format v4 round-trips for every `MessageType` |
| `handshake.*` | Stage-1 / Stage-2 / Stage-3 message shapes and signatures |
| `announce.*` | RNS announce app_data encode/decode (the v0.9.1 `{n,v,i,c,f}` schema) |
| `routing.*` | `ROUTE_ANNOUNCE` / `ROUTE_UNREACHABLE` payloads |
| `capability.*` | `CAPABILITY_ANNOUNCE` / `CAPABILITY_QUERY` payloads |

## Running the suite

```bash
# Reference implementation (Python)
pytest tests/test_conformance_vectors.py

# Other implementations: load each JSON file, run the input through
# encode → compare bytes; decode the expected_bytes_hex → compare
# decoded fields. Failure mode: print the failing vector's name +
# the first byte position that differs, exit non-zero.
```

## Adding a new vector

When the wire protocol changes (anything that bumps the protocol
version string), add a vector for the new shape. The reference
implementation's serialisation is the source of truth — generate
the new vector by running:

```bash
python tests/conformance/_emit_vectors.py --name frame.NEW_TYPE.minimal --type NEW_TYPE
```

## What's in scope

The suite covers the **wire protocol** and **announce format**.
Anything that varies legitimately between implementations
(threading model, persistence schema, log format) is **out of
scope** — the conformance promise is "two implementations talking
to each other will agree on every byte they exchange," not "two
implementations will look identical inside."

## Versioning

Vectors carry a `version` field naming the protocol version they
target. A v1.0 implementation MUST pass every `ironmesh/0.8`
vector; failure means the implementation cannot interoperate with
shipped v0.9.x peers and SHOULD NOT claim 1.0 compliance.

Future protocol versions will add new vectors in `vectors/v0.9/`,
`vectors/v1.0/`, etc. Older vectors remain valid for testing
backwards compatibility.
