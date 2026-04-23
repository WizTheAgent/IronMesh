"""IronMesh ACP — Agent Client Protocol stdio adapter.

Speaks the JSON-RPC 2.0 NDJSON wire format defined by Agent Client
Protocol (ACP) v1 (`acp-core-v1@0.3.0`, status: draft) so any
ACP-compatible client (acpx, codex, claude, droid, …) can prompt a
remote IronMesh peer as if it were a local coding agent.

Entry point: ``python -m ironmesh_acp`` or the installed
``ironmesh-acp`` console script.

Spec reference: https://agentclientprotocol.com
"""

from ironmesh_acp.server import main as _main  # noqa: F401

__all__ = ["_main"]
