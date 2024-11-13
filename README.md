# @eropple/key-sealed-envelope

**IMPORTANT NOTE:** This library has not been bulletproofed for production use. It isn't published to NPM (yet, if ever). It's likely that some obscure-ish cryptographic implementation attacks may be possible. I intend to have some generous friends review it first.

A TypeScript library for secure message sealing with multiple recipients. It's not a new idea, but I couldn't find a library that met my needs. The payload is encrypted with a symmetric key (the Content Encryption Key, or CEK), which is then encrypted with a set of all recipients' public keys. The envelope is canonicalized and signed.

Uses Web Crypto API for all cryptographic operations.

## Features

- RSA and EC support
- Multiple recipients per message; sealer classes
- JWKS key management
- Binary and string payloads
- Zero dependencies beyond Web Crypto API

## Installation

```bash
npm install @eropple/key-sealed-envelope
```

## Getting Started

In lieu of trying to explain things:

- [Quickstart example](./examples/quickstart.ts)
- [Example with EC and multiple recipients](./examples/multiple-recipients.ts)
