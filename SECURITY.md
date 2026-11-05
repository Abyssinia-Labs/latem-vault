# Security policy

OpenVault is pre-release and hasn't had a security audit. An external audit is planned before the hosted launch (design §18).

## Reporting a vulnerability

Report it privately with **Report a vulnerability** on the repository's Security tab, which opens a private advisory. Please don't open a public issue or pull request for it.

A useful report says what an attacker can do, what they need first (a stolen device, a compromised coordinator, a position on the network), and how to reproduce it.

## What counts

Anything that breaks one of the invariants in [design §4](docs/design.md#4-trust-model) (OV-1 to OV-7), or the formats in [docs/spec](docs/spec), for example:

- reading a collection without `read` or `write` scope on it;
- forging or replaying a record or membership log entry so that a device accepts it;
- getting a private key out of a key file, or out of a Secure Enclave key blob, on another machine;
- the coordinator, a relay or the network learning anything beyond what design §4 says they can see.

The known limits in design §4 aren't vulnerabilities, but reports that make them worse are welcome.

## Supported versions

There are no releases yet. Fixes go to `main`.
