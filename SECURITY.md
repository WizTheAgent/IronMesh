# Reporting Security Issues

If you believe you've found a security vulnerability in IronMesh, please
**do not** open a public GitHub issue.

## How to report

Email: **info@ironmesh.org** (or open a private security advisory via
GitHub's "Report a vulnerability" button on this repo).

Please include:

- A clear description of the vulnerability
- Steps to reproduce (if applicable, a minimal PoC)
- The IronMesh version affected
- Your assessment of impact (what can an attacker achieve?)
- Any suggested mitigation

We aim to acknowledge receipt within **48 hours** and provide a triage
assessment within **7 days**. Critical issues will be prioritized for a
point release within **14 days** of confirmation.

## Scope

**In scope** (we want to hear about these):

- Cryptographic weaknesses in the wire protocol, handshake, or trust store
- Authentication or authorization bypasses
- Remote code execution, memory corruption, or denial-of-service
  vectors against the daemon
- Information disclosure (identity keys, message plaintext, session keys)
- Flaws in the mDNS / Reticulum / LoRa integration that expose traffic
- Trust-store tampering or TOFU bypass
- Replay attacks, side channels, timing oracles

**Out of scope** (please don't send these as security reports):

- Issues in Python dependencies for which an upstream advisory already
  exists (report upstream, please)
- Attacks requiring physical access to an operator's trusted machine
  (the threat model assumes the operator's own host is trusted — see
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md))
- DoS via a legitimate-but-expensive protocol operation (e.g. sending
  the peer a huge message under the 1 MB cap); open a regular issue
  for those
- Missing TLS on the local dashboard when bound to 127.0.0.1

## Responsible disclosure

We ask for a **90-day coordinated disclosure window** from the date
we acknowledge receipt. If we haven't shipped a fix by then, you're
free to disclose publicly. If we ship a fix earlier, we'll coordinate
the disclosure timing with you and credit you in the release notes
(unless you prefer anonymity).

## The threat model

The full threat model is in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
The short version:

- IronMesh protects agent-to-agent messaging on a local network or
  LoRa radio from passive eavesdropping, active MITM (TOFU-pinned),
  and replay
- It does **not** protect against a compromised operator host, a
  compromised identity key on disk (encrypt it with a passphrase!),
  or traffic analysis (frame sizes, timing, and mDNS announces are
  observable to anyone on the LAN)
- It does **not** claim anonymity. Peer identities are deliberately
  stable — that's the point of TOFU

## Hall of fame

Security researchers who've reported valid findings will be listed
here (with their permission).

_(empty — this is the first public release. Let's fill it up.)_
