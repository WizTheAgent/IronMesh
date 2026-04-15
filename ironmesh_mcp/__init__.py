"""IronMesh MCP server.

Exposes IronMesh operations as Model Context Protocol tools so any
MCP-capable agent (Claude Desktop, Claude Code, custom clients) can
use IronMesh as a transport layer for agent-to-agent messaging.
"""

from ironmesh_mcp.server import serve

__all__ = ["serve"]
