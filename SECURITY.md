# Security Policy

## Status

ZeroStyl is under active development and has **not** been audited. It is not production-ready and is
not deployed to any mainnet. The testnet contracts on Arbitrum Sepolia currently record a proof hash
and do not yet verify the SNARK on-chain — see
[contracts/CONTRACTS.md](contracts/CONTRACTS.md) for the current security model.

## Supported versions

Only the latest `0.1.x` line receives fixes.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
| < 0.1   | ❌        |

## Reporting a vulnerability

**Do not open a public issue for security reports.**

Report privately through GitHub Security Advisories:
[**Security → Report a vulnerability**](https://github.com/kazai777/zerostyl/security/advisories/new).

We aim to acknowledge a report within 72 hours. Once a fix is ready we coordinate disclosure and
credit reporters who wish to be named. Please include a clear description, affected components, and a
minimal reproduction where possible.
