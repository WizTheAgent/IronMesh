#!/usr/bin/env bash
# rns-smoke.sh — exercises every v0.9.1 Reticulum feature end-to-end.
#
# Assumes two IronMesh daemons are running on the same host (or
# reachable via RNS), and `rnsd` is live. Intended for a parallel-
# deploy scenario where production daemons run on :8765 and the
# v0.9.1 build runs on :8866 — the smoke tests talk to the :8866 pair.
#
# Usage:
#   scripts/rns-smoke.sh <alice-dest-hash-hex> <bob-dest-hash-hex>
#
# Environment:
#   IRONMESH_RNS_CONFIGDIR   RNS config dir (default ~/.reticulum)
#   IRONMESH_PASSPHRASE      mesh passphrase for any send attempts

set -euo pipefail

ALICE_HASH="${1:-}"
BOB_HASH="${2:-}"
if [[ -z "$ALICE_HASH" || -z "$BOB_HASH" ]]; then
  echo "usage: $0 <alice-hash> <bob-hash>" >&2
  exit 2
fi

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()  { log "PASS  — $*"; }
bad() { log "FAIL  — $*"; FAIL=1; }
skip(){ log "SKIP  — $*"; }
FAIL=0

log "=== Stage 5.1: Capability RPC against Alice ==="
python - <<PY
import json, sys, time
import RNS
RNS.Reticulum()
dest_hash = bytes.fromhex("$ALICE_HASH".replace(':','').replace(' ',''))
if not RNS.Transport.has_path(dest_hash):
    RNS.Transport.request_path(dest_hash)
    await_path = getattr(RNS.Transport, 'await_path', None)
    if await_path: await_path(dest_hash, timeout=30.0)
    else:
        for _ in range(60):
            if RNS.Transport.has_path(dest_hash): break
            time.sleep(0.5)
if not RNS.Transport.has_path(dest_hash):
    print("FAIL: no path to alice", file=sys.stderr); sys.exit(1)
identity = RNS.Identity.recall(dest_hash)
if identity is None:
    print("FAIL: cannot recall identity", file=sys.stderr); sys.exit(1)
dest = RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "ironmesh", "bridge")
link = RNS.Link(dest)
for _ in range(120):
    if link.status == RNS.Link.ACTIVE: break
    time.sleep(0.25)
if link.status != RNS.Link.ACTIVE:
    print("FAIL: link never active", file=sys.stderr); sys.exit(1)
# Query /im/info
rcpt = link.request("/im/info", b"", response_callback=None)
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    if rcpt.concluded(): break
    time.sleep(0.1)
if not rcpt.concluded():
    print("FAIL: /im/info timed out", file=sys.stderr); sys.exit(1)
body = rcpt.get_response()
if body is None:
    print("FAIL: /im/info returned None", file=sys.stderr); sys.exit(1)
info = json.loads(bytes(body).decode())
print("/im/info:", json.dumps(info, indent=2))
assert info.get("name"), "name missing"
assert "resource" in info.get("features", []), "resource feature missing"
# /im/cap/list
rcpt = link.request("/im/cap/list", b"", response_callback=None)
while not rcpt.concluded(): time.sleep(0.1)
caps = json.loads(bytes(rcpt.get_response()).decode())
print("/im/cap/list:", json.dumps(caps, indent=2))
link.teardown()
print("CAPABILITY_RPC_OK")
PY
if [[ $? -eq 0 ]]; then ok "capability RPC"; else bad "capability RPC"; fi

log "=== Stage 5.2: Auto-discovery — wait for alice announce ==="
# Assumes this host's rnsd has been running long enough to hear announces.
# Uses `rnpath` to verify the path table knows about alice.
if rnpath "$ALICE_HASH" 2>&1 | grep -q "Path to"; then
  ok "alice path in local table"
else
  bad "alice not in path table — announce handler may not have fired"
fi

log "=== Stage 5.3: Admin RPC — unauthorised call returns error ==="
python - <<PY
import json, sys, time
import RNS
RNS.Reticulum()
dest_hash = bytes.fromhex("$ALICE_HASH".replace(':','').replace(' ',''))
identity = RNS.Identity.recall(dest_hash)
if identity is None: sys.exit("no identity")
dest = RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "ironmesh", "bridge")
link = RNS.Link(dest)
for _ in range(120):
    if link.status == RNS.Link.ACTIVE: break
    time.sleep(0.25)
rcpt = link.request("/im/admin/status", b"", response_callback=None)
deadline = time.monotonic() + 30
while time.monotonic() < deadline and not rcpt.concluded():
    time.sleep(0.1)
body = rcpt.get_response()
if body is None: sys.exit("admin status returned nothing")
resp = json.loads(bytes(body).decode())
print("admin status without identify:", resp)
assert resp.get("error") == "unauthorized", f"expected unauthorized, got {resp}"
link.teardown()
print("ADMIN_REJECT_OK")
PY
if [[ $? -eq 0 ]]; then ok "admin RPC rejects unauthorised"; else bad "admin RPC rejection"; fi

log "=== Summary ==="
if [[ $FAIL -eq 0 ]]; then
  log "ALL SMOKE TESTS PASSED"
  exit 0
else
  log "SMOKE FAILURES DETECTED"
  exit 1
fi
