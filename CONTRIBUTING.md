# Contributing to IronMesh

Thanks for considering a contribution. IronMesh is an early-stage
project and we want it to stay sharp — that means high test coverage,
honest documentation, and conservative protocol changes.

## Before you open a PR

1. **Run the test suite** — `pytest tests/ -q` — it should be green
   before and after your change. If you need to update a test that
   locked in the old behavior, that's fine; say so in the PR.
2. **Don't break the wire protocol** without a version negotiation path.
   IronMesh peers negotiate protocol version at handshake time. A
   wire-incompatible change needs a new version string (e.g.
   `ironmesh/0.8`) and graceful fallback for peers that don't speak it.
3. **No secrets, ever.** Passphrases, identity keys, real LAN IPs,
   internal hostnames — none of it belongs in the repo. The `.gitignore`
   excludes the common landmines. If you're unsure, ask before pushing.
4. **Explain why, not what.** A one-line PR title and a paragraph of
   context beats a twenty-line title. What problem does this solve?
   What alternatives did you consider? What could break?

## What a good PR looks like

- Scoped to one concern (one bug, one feature, one refactor — not three)
- New behavior has new tests
- Old behavior that changed has updated tests
- CHANGELOG.md gets an entry under the next-version heading
- Commit messages reference real motivations, not "WIP" or "fix"

## Areas that especially welcome help

- **More transports** — Bluetooth Low Energy, WebRTC data channels,
  Iridium SBD. The `RNSLinkAdapter` pattern (duck-types a WebSocket)
  is a good template.
- **Non-Python clients** — a Go or Rust implementation of the wire
  protocol would be great for embedded/mobile deployments. The
  [PROTOCOL_SPEC.md](docs/PROTOCOL_SPEC.md) is the authoritative reference. A Go reference implementation lives in `clients/go/`.
- **LoRa field measurements** — see [docs/LORA_VALIDATION.md](docs/LORA_VALIDATION.md).
  We have single-hop indoor numbers; multi-hop, outdoor, and high-interference
  sweeps would materially improve the project's credibility.
- **Dashboard / UX** — the current HTML dashboard is functional but
  utilitarian. Better charts, keyboard shortcuts, dark-mode sanity.
- **Threat model stress-testing** — we ship a threat model
  (docs/THREAT_MODEL.md), but adversarial review from people who do
  this for a living would be invaluable.

## Things we're unlikely to merge

- Dependencies on cloud services (IronMesh is explicitly local-first)
- Telemetry that phones home
- "Blockchain" additions that don't have a concrete threat they
  mitigate that TOFU pinning doesn't already handle
- Large-scale refactors without prior discussion in an issue
- Whitespace / style churn

## Running the tests locally

```bash
git clone <your-fork>
cd ironmesh
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e ".[dev,rns]"
pytest tests/ -v
```

Expect around 470+ passing tests and one `xpassed`. Anything else is
a regression.

## Security issues

Don't open a public issue. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed
under the [MIT License](LICENSE) that covers the project.
