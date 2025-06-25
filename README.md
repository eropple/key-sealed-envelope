# Ed's Temporal Tools

[![CI](https://github.com/eropple/key-sealed-envelope/actions/workflows/ci.yaml/badge.svg)](https://github.com/eropple/key-sealed-envelope/actions/workflows/ci.yaml)

This monorepo includes a set of tools for building an encrypted message-passing infrastructure on top of the Temporal workflow management system.

- `@eropple/key-sealed-envelope` [![NPM version](https://img.shields.io/npm/v/@eropple/key-sealed-envelope)](https://www.npmjs.com/package/@eropple/key-sealed-envelope) implements secure message sealing with multiple recipients using either RSA or EC asymmetric keys. (It's not strictly Temporal-specific, so it may be reusable for other purposes.)
- `@eropple/temporal-payload-codec` [![NPM version](https://img.shields.io/npm/v/@eropple/temporal-payload-codec)](https://www.npmjs.com/package/@eropple/temporal-payload-codec) implements a Payload Codec that handles the encryption and decryption of a payload based on the KSE sealer and unsealer above.
- `@eropple/temporal-fastify-codec-server` [![NPM version](https://img.shields.io/npm/v/@eropple/temporal-fastify-codec-server)](https://www.npmjs.com/package/@eropple/temporal-fastify-codec-server) (that's a mouthful!) implements a Fastify plugin and an example server to wrap it that uses the aforementioned data converter to enable the Temporal UI to unwrap payloads. (It's implemented as a plugin so that you can put your own authentication in front of it.)

Each package has a detailed README for your perusal.

## Thanks

- Bojan Rajkovic for initial review and feedback on `@eropple/key-sealed-envelope`
- An excellent blog post on CTX and full commitment: https://hybridkey.me/2023/02/07/aead-key-commitment.html
