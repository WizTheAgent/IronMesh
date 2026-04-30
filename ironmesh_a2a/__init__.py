"""IronMesh A2A — Agent-to-Agent HTTP gateway.

Exposes the local IronMesh node as an A2A v0.3.0 peer:

* ``GET  /.well-known/agent-card.json`` — public AgentCard with the
  node's protocol version, capabilities, and advertised skills.
* ``POST /a2a/jsonrpc`` — JSON-RPC entry for the ``message/send``
  method.
* ``POST /a2a/v1/inbox`` — direct envelope inbox for gateway-to-gateway
  command dispatch.

Authentication is bearer-token only as of v0.9.2 (set
``IRONMESH_A2A_TOKEN`` or pass ``--token``); HMAC-from-ECDH per-peer
auth remains on the post-v0.9.2 roadmap.

Entry point: ``python -m ironmesh_a2a`` or ``ironmesh-a2a``.
"""

from ironmesh_a2a.server import main as _main  # noqa: F401

__all__ = ["_main"]
