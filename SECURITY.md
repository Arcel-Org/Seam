# Security Policy

Seam is a security tool — post-quantum encrypted transport and a CLI built
on top of it. We take vulnerability reports seriously and appreciate
responsible disclosure.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately via [GitHub Security Advisories](https://github.com/Arcel-Org/Seam/security/advisories/new).
This creates a private discussion thread with maintainers and lets us
coordinate a fix and disclosure timeline before any details become public.

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce (a minimal PoC is ideal, but not required)
- Affected version(s) — see `seam version` or the `Cargo.toml` version
- Whether you're aware of it being exploited in the wild

We'll acknowledge new reports as soon as we can and keep you updated as we
investigate and fix the issue. We ask that you give us a reasonable window
to ship a fix before any public disclosure.

## Supported Versions

Seam is pre-1.0-in-spirit software under active development; the latest
release on the `main` branch is the only version that receives security
fixes. There is no long-term-support branch at this time.

## Scope

In scope:
- The `seam-protocol` library (handshake, transport, crypto, session layers)
- The `seam` CLI and its subcommands
- The build/release pipeline (`.github/workflows/`)

Out of scope:
- Vulnerabilities in third-party dependencies — please report those upstream
  (though we'd still like to know, so we can track/update accordingly)
- Denial of service against your own local machine that requires no
  network access or untrusted input (e.g. `seam` crashing on a
  deliberately malformed local config file you created yourself)

## What This Project Is (and Isn't) Claiming

Seam documents its cryptographic design and threat model in detail —
see [`docs/security.md`](docs/security.md) for the mechanisms and
[`docs/threat-model.md`](docs/threat-model.md) for the adversary model,
guarantees, and explicitly known limitations. If you believe actual
behavior diverges from what's documented there, that's a security bug —
please report it.

Seam has not undergone a formal third-party security audit. Treat it
accordingly for high-assurance use cases until one has been completed.
