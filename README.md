# @eropple/key-sealed-envelope

A TypeScript library for secure message sealing with multiple recipients. It's not a new idea, but I couldn't find a library that met my needs; I built this to act as the encrypted core of a Temporal [Data Converter](https://docs.temporal.io/dataconversion) in order to protect a given workload's data from the platform operator.

The payload is encrypted with a symmetric key (the Content Encryption Key, or CEK), which is then encrypted with a set of all recipients' public keys. The envelope is canonicalized and signed.

## Features

- RSA and EC support
- Multiple recipients per message; sealer classes
- Payload commitment ensures all recipients decrypt identical content, preventing message substitution attacks
- JWKS key management
- Binary and string payloads

## Installation

```bash
npm install @eropple/key-sealed-envelope
```

## Getting Started

In lieu of trying to explain things:

- [Quickstart example](./examples/quickstart.ts)
- [Example with EC and multiple recipients](./examples/multiple-recipients.ts)

## Thanks

- Bojan Rajkovic for initial review and feedback
- An excellent blog post on CTX and full commitment: https://hybridkey.me/2023/02/07/aead-key-commitment.html
