"""IronMesh transport abstraction layer.

Defines the base Transport interface and WebSocket implementation.
Enables future transports (TCP, QUIC, Bluetooth, LoRa) without touching protocol logic.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional

import websockets

from ironmesh.protocol import Frame

logger = logging.getLogger("ironmesh.transport")


@dataclass
class Connection:
    """Represents a connection to a peer."""
    peer_id: str
    address: str
    transport_type: str = "websocket"
    metadata: dict = field(default_factory=dict)
    _ws: Optional[websockets.WebSocketServerProtocol] = field(default=None, repr=False)

    @property
    def is_open(self) -> bool:
        if self._ws:
            return self._ws.open
        return False


class Transport(ABC):
    """Abstract base class for IronMesh transports."""

    @abstractmethod
    async def connect(self, address: str, port: int) -> Connection:
        """Connect to a remote peer."""
        ...

    @abstractmethod
    async def listen(self, host: str, port: int, handler) -> None:
        """Start listening for incoming connections."""
        ...

    @abstractmethod
    async def send(self, conn: Connection, data: bytes) -> None:
        """Send raw data over a connection."""
        ...

    @abstractmethod
    async def recv(self, conn: Connection) -> bytes:
        """Receive raw data from a connection."""
        ...

    @abstractmethod
    async def close(self, conn: Connection) -> None:
        """Close a connection."""
        ...

    @abstractmethod
    async def shutdown(self) -> None:
        """Shut down the transport."""
        ...


class WebSocketTransport(Transport):
    """WebSocket transport implementation."""

    def __init__(self, max_size: int = 1_048_576, ssl_context=None):
        self.max_size = max_size
        self.ssl_context = ssl_context
        self._server = None
        self._connections: dict[str, Connection] = {}

    async def connect(self, address: str, port: int) -> Connection:
        scheme = "wss" if self.ssl_context else "ws"
        uri = f"{scheme}://{address}:{port}"
        ws = await websockets.connect(uri, max_size=self.max_size, ssl=self.ssl_context)
        conn = Connection(
            peer_id="",  # Set after handshake
            address=f"{address}:{port}",
            transport_type="websocket",
            _ws=ws,
        )
        return conn

    async def listen(self, host: str, port: int, handler) -> None:
        self._server = await websockets.serve(
            handler,
            host,
            port,
            max_size=self.max_size,
            ssl=self.ssl_context,
        )
        logger.info("WebSocket transport listening on %s:%d", host, port)

    async def send(self, conn: Connection, data: bytes) -> None:
        if conn._ws and conn._ws.open:
            await conn._ws.send(data)
        else:
            raise ConnectionError(f"Connection to {conn.peer_id} is closed")

    async def recv(self, conn: Connection, timeout: float = 300.0) -> bytes:
        """Receive with a bounded wait (audit H-06).

        A stalled peer must not block this coroutine forever. Default
        timeout is 5 minutes — callers can pass a shorter value for
        latency-sensitive paths.
        """
        if conn._ws:
            data = await asyncio.wait_for(conn._ws.recv(), timeout=timeout)
            return data.encode() if isinstance(data, str) else data
        raise ConnectionError(f"Connection to {conn.peer_id} is closed")

    async def close(self, conn: Connection) -> None:
        if conn._ws:
            await conn._ws.close()

    async def shutdown(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def iter_messages(self, conn: Connection) -> AsyncIterator[bytes]:
        """Iterate over incoming messages on a connection."""
        if conn._ws:
            async for msg in conn._ws:
                yield msg.encode() if isinstance(msg, str) else msg
