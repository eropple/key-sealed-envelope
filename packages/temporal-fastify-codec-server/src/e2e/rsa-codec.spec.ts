import {
  type RSAPrivateNamedJWK,
  type RSAPublicNamedJWK,
  type RSAPublicNamedJWKS,
} from "@eropple/key-sealed-envelope";
import {
  KeySealedEnvelopeRSACodec,
  type KeySealedEnvelopeRSACodecOptions,
} from "@eropple/temporal-payload-codec";
import { type Payload } from "@temporalio/common";
import fastify, { type FastifyInstance } from "fastify";
import { beforeAll, describe, expect, it } from "vitest";

import { temporalCodecPlugin } from "../index.js";

// --- Payload Helpers ---

interface JSONPayload {
  metadata?: Record<string, string> | null;
  data?: string | null;
}

function toJSON({ metadata, data }: Payload): JSONPayload {
  return {
    metadata: metadata
      ? Object.fromEntries(
          Object.entries(metadata).map(([k, v]): [string, string] => [
            k,
            Buffer.from(v).toString("base64"),
          ])
        )
      : null,
    data: data ? Buffer.from(data).toString("base64") : null,
  };
}

// --- Key Generation ---
async function generateKeys() {
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

  const [
    clientSigningKeys,
    clientEncryptionKeys,
    workerSigningKeys,
    workerEncryptionKeys,
    serverSigningKeys,
    serverEncryptionKeys,
    mallorySigningKeys,
    malloryEncryptionKeys,
  ] = await Promise.all([
    generateSigningKeyPair(),
    generateEncryptionKeyPair(),
    generateSigningKeyPair(),
    generateEncryptionKeyPair(),
    generateSigningKeyPair(),
    generateEncryptionKeyPair(),
    generateSigningKeyPair(),
    generateEncryptionKeyPair(),
  ]);

  const toPrivateJWK = async (
    key: CryptoKey,
    kid: string
  ): Promise<RSAPrivateNamedJWK> => ({
    ...((await crypto.subtle.exportKey("jwk", key)) as RSAPrivateNamedJWK),
    kid,
    kty: "RSA",
  });

  const toPublicJWK = async (
    key: CryptoKey,
    kid: string
  ): Promise<RSAPublicNamedJWK> => ({
    ...((await crypto.subtle.exportKey("jwk", key)) as RSAPublicNamedJWK),
    kid,
    kty: "RSA",
  });

  const clientSigningPrivateJWK = await toPrivateJWK(
    clientSigningKeys.privateKey,
    "client-1"
  );
  const clientSigningPublicJWK = await toPublicJWK(
    clientSigningKeys.publicKey,
    "client-1"
  );
  const clientDecryptionPrivateJWK = await toPrivateJWK(
    clientEncryptionKeys.privateKey,
    "client-1"
  );
  const clientEncryptionPublicJWK = await toPublicJWK(
    clientEncryptionKeys.publicKey,
    "client-1"
  );

  const workerSigningPrivateJWK = await toPrivateJWK(
    workerSigningKeys.privateKey,
    "worker-1"
  );
  const workerSigningPublicJWK = await toPublicJWK(
    workerSigningKeys.publicKey,
    "worker-1"
  );
  const workerDecryptionPrivateJWK = await toPrivateJWK(
    workerEncryptionKeys.privateKey,
    "worker-1"
  );
  const workerEncryptionPublicJWK = await toPublicJWK(
    workerEncryptionKeys.publicKey,
    "worker-1"
  );

  const serverSigningPrivateJWK = await toPrivateJWK(
    serverSigningKeys.privateKey,
    "codecserver-1"
  );
  const serverSigningPublicJWK = await toPublicJWK(
    serverSigningKeys.publicKey,
    "codecserver-1"
  );
  const serverDecryptionPrivateJWK = await toPrivateJWK(
    serverEncryptionKeys.privateKey,
    "codecserver-1"
  );
  const serverEncryptionPublicJWK = await toPublicJWK(
    serverEncryptionKeys.publicKey,
    "codecserver-1"
  );

  const mallorySigningPrivateJWK = await toPrivateJWK(
    mallorySigningKeys.privateKey,
    "mallory-1"
  );
  const malloryDecryptionPrivateJWK = await toPrivateJWK(
    malloryEncryptionKeys.privateKey,
    "mallory-1"
  );

  const recipientPublicKeys: RSAPublicNamedJWKS = {
    keys: [
      clientEncryptionPublicJWK,
      workerEncryptionPublicJWK,
      serverEncryptionPublicJWK,
    ],
  };

  const senderPublicKeys: RSAPublicNamedJWKS = {
    keys: [
      clientSigningPublicJWK,
      workerSigningPublicJWK,
      serverSigningPublicJWK,
    ],
  };

  return {
    clientSigningPrivateJWK,
    clientDecryptionPrivateJWK,
    workerSigningPrivateJWK,
    workerDecryptionPrivateJWK,
    serverSigningPrivateJWK,
    serverDecryptionPrivateJWK,
    mallorySigningPrivateJWK,
    malloryDecryptionPrivateJWK,
    recipientPublicKeys,
    senderPublicKeys,
  };
}

// --- Tests ---

describe("e2e: KeySealedEnvelopeRSACodec with temporalCodecPlugin", () => {
  let clientCodec: KeySealedEnvelopeRSACodec;
  let workerCodec: KeySealedEnvelopeRSACodec;
  let serverCodec: KeySealedEnvelopeRSACodec;
  let malloryCodec: KeySealedEnvelopeRSACodec;

  let server: FastifyInstance;

  beforeAll(async () => {
    const keys = await generateKeys();

    const clientOptions: KeySealedEnvelopeRSACodecOptions = {
      ownSigningKey: keys.clientSigningPrivateJWK,
      ownDecryptionKey: keys.clientDecryptionPrivateJWK,
      recipientPublicKeys: keys.recipientPublicKeys,
      senderPublicKeys: keys.senderPublicKeys,
    };
    clientCodec = new KeySealedEnvelopeRSACodec(clientOptions);

    const workerOptions: KeySealedEnvelopeRSACodecOptions = {
      ownSigningKey: keys.workerSigningPrivateJWK,
      ownDecryptionKey: keys.workerDecryptionPrivateJWK,
      recipientPublicKeys: keys.recipientPublicKeys,
      senderPublicKeys: keys.senderPublicKeys,
    };
    workerCodec = new KeySealedEnvelopeRSACodec(workerOptions);

    const serverOptions: KeySealedEnvelopeRSACodecOptions = {
      ownSigningKey: keys.serverSigningPrivateJWK,
      ownDecryptionKey: keys.serverDecryptionPrivateJWK,
      recipientPublicKeys: keys.recipientPublicKeys,
      senderPublicKeys: keys.senderPublicKeys,
    };
    serverCodec = new KeySealedEnvelopeRSACodec(serverOptions);

    const malloryOptions: KeySealedEnvelopeRSACodecOptions = {
      ownSigningKey: keys.mallorySigningPrivateJWK,
      ownDecryptionKey: keys.malloryDecryptionPrivateJWK,
      recipientPublicKeys: keys.recipientPublicKeys,
      senderPublicKeys: keys.senderPublicKeys,
    };
    malloryCodec = new KeySealedEnvelopeRSACodec(malloryOptions);
  });

  const createSamplePayload = (message: string): Payload => ({
    metadata: {
      "message.encoding": new TextEncoder().encode("json/plain"),
    },
    data: new TextEncoder().encode(JSON.stringify({ message })),
  });

  describe("happy path", () => {
    it("should decode a payload from a client", async () => {
      server = fastify();
      await server.register(temporalCodecPlugin, { codec: serverCodec });

      const originalPayload = createSamplePayload("hello from client");
      const encoded = await clientCodec.encode([originalPayload]);

      const response = await server.inject({
        method: "POST",
        url: "/decode",
        payload: {
          payloads: encoded.map(toJSON),
        },
      });

      expect(response.statusCode).toBe(200);
      const body = response.json();
      expect(body.payloads[0].metadata["message.encoding"]).toEqual(
        "anNvbi9wbGFpbg=="
      ); // json/plain in base64
      expect(body.payloads[0].data).toEqual(
        "eyJtZXNzYWdlIjoiaGVsbG8gZnJvbSBjbGllbnQifQ=="
      ); // {"message":"hello from client"} in base64
    });

    it("should encode a payload for a worker", async () => {
      server = fastify();
      await server.register(temporalCodecPlugin, { codec: serverCodec });

      const originalPayload = createSamplePayload("hello to worker");

      const response = await server.inject({
        method: "POST",
        url: "/encode",
        payload: {
          payloads: [toJSON(originalPayload)],
        },
      });

      expect(response.statusCode).toBe(200);
      const body = response.json();

      const encodedPayload: Payload = {
        metadata: {
          encoding: Buffer.from(body.payloads[0].metadata.encoding, "base64"),
        },
        data: Buffer.from(body.payloads[0].data, "base64"),
      };

      const decoded = await workerCodec.decode([encodedPayload]);
      expect(decoded[0]).toEqual(originalPayload);
    });
  });

  describe("sad path", () => {
    it("should fail to decode a payload from an untrusted sender (Mallory)", async () => {
      server = fastify();
      await server.register(temporalCodecPlugin, { codec: serverCodec });

      const originalPayload = createSamplePayload("evil message");
      const encoded = await malloryCodec.encode([originalPayload]);

      const response = await server.inject({
        method: "POST",
        url: "/decode",
        payload: {
          payloads: encoded.map(toJSON),
        },
      });

      expect(response.statusCode).toBe(500);
    });

    it("should fail to decode a payload not intended for the server", async () => {
      server = fastify();
      await server.register(temporalCodecPlugin, { codec: serverCodec });

      // Re-create a client codec that doesn't know about the server's public key
      const keys = await generateKeys();
      const limitedClientOptions: KeySealedEnvelopeRSACodecOptions = {
        ownSigningKey: keys.clientSigningPrivateJWK,
        ownDecryptionKey: keys.clientDecryptionPrivateJWK,
        recipientPublicKeys: {
          keys: keys.recipientPublicKeys.keys.filter(
            (k) => k.kid !== "codecserver-1"
          ),
        },
        senderPublicKeys: keys.senderPublicKeys,
      };
      const limitedClientCodec = new KeySealedEnvelopeRSACodec(
        limitedClientOptions
      );

      const originalPayload = createSamplePayload("secret message for worker");
      const encoded = await limitedClientCodec.encode([originalPayload]);

      const response = await server.inject({
        method: "POST",
        url: "/decode",
        payload: {
          payloads: encoded.map(toJSON),
        },
      });

      expect(response.statusCode).toBe(500);
    });
  });
});
