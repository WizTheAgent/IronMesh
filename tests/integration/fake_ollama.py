"""Deterministic fake Ollama server for integration tests.

Mimics enough of the real Ollama HTTP API that ``examples/llm_bridge.py``
can't tell the difference. Every response is a pure function of the
prompt, so test assertions are stable across runs and platforms.

Endpoints
---------

``POST /api/generate``
    Accepts the Ollama JSON body ``{model, prompt, system?, stream?}``.
    Returns ``{response: "<canned reply>", done: true, ...}``.
    The reply text is the string returned by ``responder(prompt, model)``
    passed into ``FakeOllama(responder=...)``. The default responder
    returns ``"reply-to:" + prompt`` so tests can pattern-match.

``GET /api/tags``
    Returns ``{models: [{name: "fake-model:latest", size: 1}]}`` so
    tests that pre-flight the model list don't choke.

Usage in a test
---------------

    from tests.integration.fake_ollama import FakeOllama

    def test_llm_bridge_round_trip():
        fake = FakeOllama(port=0)  # pick a free port
        fake.start()
        try:
            # point llm_bridge.py at fake.url
            ...
        finally:
            fake.stop()

The server runs on its own thread and listens on ``127.0.0.1`` only,
so it's safe to stand up in CI alongside other tests.
"""
from __future__ import annotations

import http.server
import json
import threading
import time
from typing import Callable, Optional


def _default_responder(prompt: str, model: str) -> str:
    """Echo the prompt back with a tag. Deterministic; no randomness."""
    return f"reply-to:{prompt.strip()}"


class FakeOllamaHandler(http.server.BaseHTTPRequestHandler):
    # Server-scoped config; set by FakeOllama.start().
    responder: Callable[[str, str], str]
    seen_prompts: list[tuple[str, str]]
    artificial_delay: float = 0.0

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        # Stay silent; pytest captures stderr but we don't want noise.
        pass

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/api/tags":
            body = json.dumps({
                "models": [{
                    "name": "fake-model:latest",
                    "size": 1,
                    "modified_at": "2026-01-01T00:00:00Z",
                }],
            }).encode()
            self._send(200, body, "application/json")
            return
        self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/generate":
            self._send(404, b"not found", "text/plain")
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            self._send(400, b'{"error":"bad json"}', "application/json")
            return
        prompt = body.get("prompt", "")
        model = body.get("model", "fake-model:latest")
        type(self).seen_prompts.append((model, prompt))
        if type(self).artificial_delay:
            time.sleep(type(self).artificial_delay)
        try:
            text = type(self).responder(prompt, model)
        except Exception as e:  # noqa: BLE001
            # Report as an Ollama-style error.
            self._send(500, json.dumps({"error": str(e)}).encode(), "application/json")
            return
        resp = {
            "model": model,
            "response": text,
            "done": True,
            "total_duration": 1,
            "load_duration": 0,
            "prompt_eval_count": len(prompt),
            "eval_count": len(text),
        }
        self._send(200, json.dumps(resp).encode(), "application/json")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeOllama:
    """Context-managed fake Ollama server.

    Parameters
    ----------
    port : int
        TCP port to bind on ``127.0.0.1``. Pass ``0`` to let the kernel
        assign one; read ``self.port`` after ``start()``.
    responder : callable (prompt, model) -> str
        Returns the text sent back as the generated response.
    """

    def __init__(
        self,
        port: int = 0,
        responder: Callable[[str, str], str] = _default_responder,
        artificial_delay: float = 0.0,
    ) -> None:
        self.port = port
        self.responder = responder
        self.artificial_delay = artificial_delay
        self._server: Optional[http.server.HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.seen_prompts: list[tuple[str, str]] = []

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        # Build a handler class that closes over our config so multiple
        # FakeOllama instances don't share state.
        handler_cls = type(
            f"FakeOllamaHandler_{id(self)}",
            (FakeOllamaHandler,),
            {
                "responder": staticmethod(self.responder),
                "seen_prompts": self.seen_prompts,
                "artificial_delay": self.artificial_delay,
            },
        )
        self._server = http.server.HTTPServer(("127.0.0.1", self.port), handler_cls)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name=f"fake-ollama-{self.port}",
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    def __enter__(self) -> "FakeOllama":
        self.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.stop()
