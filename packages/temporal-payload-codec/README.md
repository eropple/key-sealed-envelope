# `@eropple/temporal-payload-codec`

[![NPM version](https://img.shields.io/npm/v/@eropple/temporal-payload-codec)](https://www.npmjs.com/package/@eropple/temporal-payload-codec)

This package provides a [Temporal.io](https://temporal.io/) `PayloadCodec` that uses [`@eropple/key-sealed-envelope`](https://www.npmjs.com/package/@eropple/key-sealed-envelope) to provide strong, end-to-end encryption for all data flowing through a Temporal cluster.

It ensures that all sensitive application data (workflow arguments, activity results, signals, etc.) exists unencrypted only on the Client and Worker processes that you control. The Temporal service itself never has access to the unencrypted data.

## Features

- **End-to-End Encryption**: Payloads are encrypted on the client and only decrypted by the worker, and vice-versa.
- **Sender Authentication**: All encrypted payloads are digitally signed, preventing tampering and verifying the sender's identity.
- **Multiple Key Types**: Supports both `RSA` and Elliptic-Curve (`EC`) keys.
- **Flexible Key Management**: Designed to work with keys you load from a secure vault or KMS.

## Installation

```bash
pnpm add @eropple/temporal-payload-codec @temporalio/client @temporalio/worker
```

## How It Works

This library provides two `PayloadCodec` implementations: `KeySealedEnvelopeRSACodec` and `KeySealedEnvelopeECCodec`. When you configure a Temporal Client or Worker with one of these codecs, it intercepts all incoming and outgoing data payloads.

- **On `encode` (sending data)**: The codec uses your private signing key and the public encryption keys of your intended recipients to seal the payload in a secure envelope.
- **On `decode` (receiving data)**: The codec uses your private encryption key to open the envelope and the sender's public signing key to verify its authenticity before passing the decrypted data to your application.

## Configuration

To use one of the codecs, you must provide it with a configuration object containing four distinct sets of keys.

- `ownSigningKey`: The **private signing key** (e.g., `RSA-PSS` or `ECDSA`) for this specific entity (Client or Worker). It is used to prove to other parties that you are who you say you are.
- `ownDecryptionKey`: The **private encryption key** (e.g., `RSA-OAEP` or `ECDH`). This is your secret key, used to decrypt messages sent specifically to you.
- `recipientPublicKeys`: A JWKS containing the **public encryption keys** of all other parties. When you send a message, you will use these keys to ensure only your intended recipients can read it.
- `senderPublicKeys`: A JWKS containing the **public signing keys** of all other parties. You use these to verify that incoming messages were actually sent by who they claim to be from.

## Getting Started Example (RSA)

Here is a complete example of how to configure a Temporal Client and Worker to communicate securely.

### 1. Key Generation

In a real application, you would load these keys from a secure source. For this example, we'll generate them.

```typescript
import {
  type RSAPrivateNamedJWK,
  type RSAPublicNamedJWK,
  type RSAPublicNamedJWKS,
} from "@eropple/key-sealed-envelope";

// Helper to generate an RSA-PSS key pair for signing
const generateSigningKeyPair = () =>
  crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );

// Helper to generate an RSA-OAEP key pair for encryption
const generateEncryptionKeyPair = () =>
  crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
```

### 2. Data Converter Setup

Create a `data-converter.ts` file. This is where you will configure the codec.

```typescript
// src/data-converter.ts
import {
  KeySealedEnvelopeRSACodec,
  type KeySealedEnvelopeRSACodecOptions,
} from "@eropple/temporal-payload-codec";
import type { DataConverter } from "@temporalio/common";

export function createDataConverter(
  options: KeySealedEnvelopeRSACodecOptions
): DataConverter {
  return {
    payloadCodecs: [new KeySealedEnvelopeRSACodec(options)],
  };
}
```

### 3. Client and Worker Integration

Now, instantiate your Temporal Client and Worker, providing the `DataConverter` with the correct keys.

```typescript
import { Client, Connection, Worker } from "@temporalio/client";
import { createDataConverter } from "./data-converter";

async function run() {
  // --- 1. Generate all necessary keys ---
  const [clientSigning, clientEncryption, workerSigning, workerEncryption] =
    await Promise.all([
      generateSigningKeyPair(),
      generateEncryptionKeyPair(),
      generateSigningKeyPair(),
      generateEncryptionKeyPair(),
    ]);

  // --- 2. Create JWKs for all keys ---
  // (In a real app, these would be loaded from your key management system)
  const clientSigningPrivateJWK = toPrivateJWK(clientSigning.privateKey, "client-signer");
  const clientSigningPublicJWK = toPublicJWK(clientSigning.publicKey, "client-signer");
  const clientDecryptionPrivateJWK = toPrivateJWK(clientEncryption.privateKey, "client-encrypter");
  const clientEncryptionPublicJWK = toPublicJWK(clientEncryption.publicKey, "client-encrypter");
  const workerSigningPrivateJWK = toPrivateJWK(workerSigning.privateKey, "worker-signer");
  const workerSigningPublicJWK = toPublicJWK(workerSigning.publicKey, "worker-signer");
  const workerDecryptionPrivateJWK = toPrivateJWK(workerEncryption.privateKey, "worker-encrypter");
  const workerEncryptionPublicJWK = toPublicJWK(workerEncryption.publicKey, "worker-encrypter");


  // --- 3. Assemble the public key sets (JWKS) ---
  const recipientPublicKeys: RSAPublicNamedJWKS = {
    keys: [clientEncryptionPublicJWK, workerEncryptionPublicJWK],
  };
  const senderPublicKeys: RSAPublicNamedJWKS = {
    keys: [clientSigningPublicJWK, workerSigningPublicJWK],
  };

  // --- 4. Configure and create the Client's DataConverter ---
  const clientDataConverter = createDataConverter({
    ownSigningKey: clientSigningPrivateJWK,
    ownDecryptionKey: clientDecryptionPrivateJWK,
    recipientPublicKeys,
    senderPublicKeys,
  });

  const client = new Client({
    dataConverter: clientDataConverter,
    // ... other client options
  });

  // --- 5. Configure and create the Worker's DataConverter ---
   const workerDataConverter = createDataConverter({
    ownSigningKey: workerSigningPrivateJWK,
    ownDecryptionKey: workerDecryptionPrivateJWK,
    recipientPublicKeys,
    senderPublicKeys,
  });

  const worker = await Worker.create({
    // ... your workflow and activity paths
    taskQueue: 'my-secure-queue',
    dataConverter: workerDataConverter,
  });

  // Now, all data sent via `client` and processed by `worker` is secure.
}

// Helper to convert CryptoKey to JWK - for demonstration only.
async function toPrivateJWK(key: CryptoKey, kid: string): Promise<RSAPrivateNamedJWK> {
  // ... implementation ...
}
async function toPublicJWK(key: CryptoKey, kid: string): Promise<RSAPublicNamedJWK> {
  // ... implementation ...
}

run().catch(console.error);
```
