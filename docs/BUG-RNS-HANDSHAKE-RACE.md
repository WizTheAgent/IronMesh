# BUG: RNS Handshake Race Condition (v0.5.0)

**Status:** Fixed  
**Severity:** Critical — prevents all IronMesh-over-Reticulum connections  
**Affected versions:** v0.5.0  
**Fixed in:** v0.5.1  
**File:** `reticulum_transport.py`

---

## Symptom

When two IronMesh nodes attempt to connect over Reticulum (LoRa or TCP),
the **outbound** side logs `RNS link established` but the IronMesh
passphrase handshake **never completes**.  Both sides time out after 30
seconds.  WebSocket transport between the same nodes works perfectly.

Observable behavior:

- Wiz (initiator) logs: `RNS link established to <dest_hash>`
- KingPi (receiver) logs: `Handshake failed:` (empty — timeout)
- No `PASSPHRASE_CHALLENGE` is ever received by the initiator
- `rnpath` resolves fine in both directions
- Raw `RNS.Link` establishment works (4 ms RTT over TCP)

---

## Root Cause Analysis

### Primary: Packet callback race in `connect_to_destination` (CRITICAL)

In `ReticulumTransport.connect_to_destination()`, the code created the
`RNSLinkAdapter` **after** waiting for the link to become `ACTIVE`:

```python
# BEFORE (buggy)
link = RNS.Link(destination)

while link.status != RNS.Link.ACTIVE:   # wait...
    await asyncio.sleep(0.25)

link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
adapter = RNSLinkAdapter(link, ...)       # callbacks set HERE — too late!
```

The `RNSLinkAdapter.__init__` registers `set_packet_callback` on the
link.  But the remote side's `_handle_connection` sends the
`PASSPHRASE_CHALLENGE` the instant the link goes `ACTIVE`.  On LoRa
(3 kbps) there is enough latency that the race rarely triggers, but over
TCP (sub-millisecond) the challenge packet arrives **before** the adapter
exists.  RNS delivers the packet to a link with no callback registered
and silently drops it.

**Timeline of the race:**

```
t=0    Wiz: RNS.Link(destination) — link handshake begins
t=4ms  Both: link status → ACTIVE
t=4ms  KingPi: _on_incoming_link fires → adapter created → _handle_connection scheduled
t=5ms  KingPi: _handle_connection sends PASSPHRASE_CHALLENGE over RNS link
t=5ms  Wiz: PASSPHRASE_CHALLENGE packet arrives — NO CALLBACK REGISTERED → dropped
t=5ms  Wiz: connect_to_destination exits wait loop, creates adapter (too late)
t=5ms  Wiz: _do_client_handshake calls adapter.recv() — waits forever
t=35s  Both: timeout → "Handshake failed"
```

### Secondary: Silent exception swallowing in `_on_incoming_link`

The `_on_incoming_link` callback runs on the **RNS transport thread**.
Any unhandled Python exception in this callback is silently swallowed by
RNS's internal callback dispatch — no log, no traceback, nothing.  The
original code had no try/except wrapper, making debugging nearly
impossible.

Additionally, `link.get_remote_identity().hash` was evaluated
unconditionally in the `RNS.prettyhexrep()` call, which would
`AttributeError` if `get_remote_identity()` returned `None`.  The
ternary guard called `get_remote_identity()` twice (once for the check,
once for the value), introducing a TOCTOU race in a multithreaded
context.

### Tertiary: Lambda late-binding in `call_soon_threadsafe`

```python
# BEFORE (subtle bug)
self._loop.call_soon_threadsafe(
    lambda: asyncio.ensure_future(
        self._daemon._handle_connection(adapter)
    ),
)
```

The `adapter` variable is captured by reference in the lambda closure.
If `_on_incoming_link` were ever called twice in rapid succession, both
lambdas would reference the **last** adapter.  Fixed by using a
default-argument capture: `lambda a=adapter: ...`.

---

## Fix

### 1. Register callbacks BEFORE link goes ACTIVE

```python
# AFTER (fixed)
link = RNS.Link(destination)

# Create adapter immediately — callbacks are set in __init__
link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
adapter = RNSLinkAdapter(link, self._loop, dest_hash_hex=dest_hash_hex)

while link.status != RNS.Link.ACTIVE:   # now safe to wait
    await asyncio.sleep(0.25)

self._active_adapters.append(adapter)
```

The `RNSLinkAdapter` constructor calls `link.set_packet_callback()`
which registers the handler.  By creating the adapter before the link
becomes `ACTIVE`, the callback is in place when the first packet arrives.

### 2. Wrap `_on_incoming_link` in try/except with logging

```python
def _on_incoming_link(self, link) -> None:
    try:
        logger.info("Incoming RNS link from %s", ...)
        # ... adapter creation, scheduling ...
    except Exception:
        logger.exception("_on_incoming_link crashed")
```

### 3. Safe identity extraction + lambda capture

```python
remote = "unknown"
try:
    ri = link.get_remote_identity()
    if ri:
        remote = RNS.prettyhexrep(ri.hash)
except Exception:
    pass

self._loop.call_soon_threadsafe(
    lambda a=adapter: asyncio.ensure_future(
        self._daemon._handle_connection(a)
    ),
)
```

---

## How to reproduce (before fix)

1. Start two IronMesh nodes on the same LAN with Reticulum enabled
2. Ensure both have `rnsd` running with a TCP link between them
3. Start node A with `--rns-connect <node_B_dest_hash>`
4. Observe: node A logs `RNS link established` but no handshake follows
5. After 30 s, node B logs `Handshake failed:`

## Additional bugs found during fix

### Bug 2: `RNS.Resource` BytesIO missing `.name` attribute

`RNSLinkAdapter.send()` used `io.BytesIO` for payloads > 400 bytes,
but `RNS.Resource()` expects a file-like object with a `.name`
attribute (a real filesystem path).  `BytesIO` has no `.name`, causing
`AttributeError`.  Setting `.name` to a dummy string made RNS try to
`open()` it as a file path (`[WinError 2]`).

**Fix:** Use `tempfile.mkstemp()` to write data to a real file, pass
an `open()` file handle to `RNS.Resource`, and clean up in the
Resource's concluded callback.

### Bug 3: Packet callbacks vs RNS link handshake

Setting `link.set_packet_callback()` before the link reaches `ACTIVE`
status interferes with RNS's internal link establishment handshake,
preventing the link from ever going ACTIVE.  The adapter MUST be
created after the link is established.

**Fix:** Keep the original order (adapter after ACTIVE) but add a
1.5 s delay in `_on_incoming_link` before dispatching
`_handle_connection`, giving the outbound side time to register its
callbacks.

### Bug 4: Raw Packets + Resources are the wrong RNS API

The original `RNSLinkAdapter` used `RNS.Packet` for small messages
(< 400 bytes) and `RNS.Resource` for larger ones.  This had several
issues:

- `set_packet_callback` conflicts with RNS internal link management
- Resource transfers require real file handles (BytesIO doesn't work)
- No automatic fragmentation, ordering, or delivery acknowledgment
- The 798-byte HELLO message exceeded the 431-byte packet MDU

**Fix:** Complete rewrite of `RNSLinkAdapter` to use
`RNS.Buffer.create_bidirectional_buffer()` over the link's Channel.
This provides:

- Automatic fragmentation and reassembly (handles any message size)
- Reliable delivery with retries
- Bidirectional streaming with stream ID coordination
- No temp files or manual MDU management

Messages are length-prefixed (4-byte big-endian) within the Buffer
stream, giving discrete message boundaries on top of the byte stream.

Server side uses stream IDs `(recv=0, send=1)`, client uses
`(recv=1, send=0)`, passed via the `is_server` parameter.

## How to verify (after fix)

1. Same setup as above
2. Node A logs `RNS link established to <hash>`
3. Node B logs `Incoming RNS link from <hash>`
4. Both complete the passphrase + ECDH handshake
5. Encrypted messages flow over the Reticulum transport

---

## Lessons learned

1. **Register callbacks before events, not after.** In any async or
   event-driven system, if you create a resource that can receive events,
   register your handlers first.  "Create → wait → handle" is a race;
   "create → handle → wait" is safe.

2. **Never let exceptions vanish silently in cross-thread callbacks.**
   RNS runs callbacks on its own thread and swallows exceptions.  Always
   wrap thread-boundary callbacks in try/except with explicit logging.

3. **Capture loop variables in lambdas with default arguments.**
   `lambda a=adapter:` is immune to late-binding; `lambda: ...adapter...`
   is not.
