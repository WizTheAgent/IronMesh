# IronMesh — zero-config encrypted agent-to-agent protocol
# Multi-stage build, non-root user, runs as UID 1000.
#
# Build:   docker build -t ironmesh:0.9.5 .
# Run:     docker run --rm -it -p 8765:8765 -p 8766:8766 \
#              -e IRONMESH_PASSPHRASE=mysecretpassphrase \
#              -v ironmesh-data:/data/ironmesh \
#              ironmesh:0.9.5

FROM python:3.13-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
# Package source lives at repo root (pyproject.toml: package-dir.ironmesh = ".")
COPY *.py ./
COPY adapters ./adapters
COPY ironmesh_mcp ./ironmesh_mcp
COPY ironmesh_acp ./ironmesh_acp
COPY ironmesh_a2a ./ironmesh_a2a
COPY examples ./examples

RUN pip install --prefix=/install --no-cache-dir ".[rns]"


# ---------------------------------------------------------------------------
FROM python:3.13-slim-bookworm

LABEL org.opencontainers.image.title="IronMesh"
LABEL org.opencontainers.image.description="Zero-config encrypted agent-to-agent mesh protocol"
LABEL org.opencontainers.image.source="https://github.com/WizTheAgent/IronMesh"
LABEL org.opencontainers.image.licenses="MIT"

RUN apt-get update && apt-get install -y --no-install-recommends \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 ironmesh \
    && useradd --uid 1000 --gid ironmesh --shell /bin/bash --create-home ironmesh \
    && mkdir -p /data/ironmesh /data/reticulum \
    && chown -R ironmesh:ironmesh /data

COPY --from=builder /install /usr/local

# Map the default IronMesh paths into the data volumes
RUN ln -s /data/ironmesh /home/ironmesh/.ironmesh \
    && ln -s /data/reticulum /home/ironmesh/.reticulum \
    && chown -h ironmesh:ironmesh /home/ironmesh/.ironmesh /home/ironmesh/.reticulum

USER ironmesh
WORKDIR /home/ironmesh

# Ports: 8765 bridge WS, 8766 GUI dashboard (bound to 127.0.0.1 inside container by default)
EXPOSE 8765 8766

VOLUME ["/data/ironmesh", "/data/reticulum"]

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    IRONMESH_NAME=ironmesh-docker \
    IRONMESH_PORT=8765

ENTRYPOINT ["/usr/bin/tini", "--"]
# Secure default: default-deny discovery (auto-connect needs --allowed-peers)
# and wss-first (no ws:// fallback). The two INSECURE convenience flags
# (--open-discovery, --allow-plaintext-ws) are deliberately NOT in the shipped
# default — a pulled-and-run image must not silently disable peer allowlisting
# and TLS. To run the isolated zero-config demo, pass them explicitly (see
# docker-compose.demo.yml or the README "Docker" section).
CMD ["sh", "-c", "ironmesh run --name ${IRONMESH_NAME} --port ${IRONMESH_PORT} --bind 0.0.0.0 --gui"]
