import {
  type ECPrivateNamedJWK,
  type ECPublicNamedJWK,
  type ECPublicNamedJWKS,
} from "@eropple/key-sealed-envelope";
import {
  KeySealedEnvelopeECCodec,
  type KeySealedEnvelopeECCodecOptions,
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
    crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ]);
  const generateEncryptionKeyPair = () =>
    crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
      "deriveKey",
    ]);

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
  ): Promise<ECPrivateNamedJWK> => ({
    ...((await crypto.subtle.exportKey("jwk", key)) as ECPrivateNamedJWK),
    kid,
    kty: "EC",
    crv: "P-256",
  });

  const toPublicJWK = async (
    key: CryptoKey,
    kid: string
  ): Promise<ECPublicNamedJWK> => ({
    ...((await crypto.subtle.exportKey("jwk", key)) as ECPublicNamedJWK),
    kid,
    kty: "EC",
    crv: "P-256",
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

  const recipientPublicKeys: ECPublicNamedJWKS = {
    keys: [
      clientEncryptionPublicJWK,
      workerEncryptionPublicJWK,
      serverEncryptionPublicJWK,
    ],
  };

  const senderPublicKeys: ECPublicNamedJWKS = {
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

describe("e2e: KeySealedEnvelopeECCodec with temporalCodecPlugin", () => {
  let clientCodec: KeySealedEnvelopeECCodec;
  let workerCodec: KeySealedEnvelopeECCodec;
  let serverCodec: KeySealedEnvelopeECCodec;
  let malloryCodec: KeySealedEnvelopeECCodec;

  let server: FastifyInstance;

  beforeAll(async () => {
    const keys = await generateKeys();

    const clientOptions: KeySealedEnvelopeECCodecOptions = {
      ownSigningKey: keys.clientSigningPrivateJWK,
      ownDecryptionKey: keys.clientDecryptionPrivateJWK,
      recipientPublicKeys: keys.recipientPublicKeys,
      senderPublicKeys: keys.senderPublicKeys,
    };
    clientCodec = new KeySealedEnvelopeECCodec(clientOptions);

    const workerOptions: KeySealedEnvelopeECCodecOptions = {
      ownSigningKey: keys.workerSigningPrivateJWK,
      ownDecryptionKey: keys.workerDecryptionPrivateJWK,
      recipientPublicKeys: keys.recipientPublicKeys,
      senderPublicKeys: keys.senderPublicKeys,
    };
    workerCodec = new KeySealedEnvelopeECCodec(workerOptions);

    const serverOptions: KeySealedEnvelopeECCodecOptions = {
      ownSigningKey: keys.serverSigningPrivateJWK,
      ownDecryptionKey: keys.serverDecryptionPrivateJWK,
      recipientPublicKeys: keys.recipientPublicKeys,
      senderPublicKeys: keys.senderPublicKeys,
    };
    serverCodec = new KeySealedEnvelopeECCodec(serverOptions);

    const malloryOptions: KeySealedEnvelopeECCodecOptions = {
      ownSigningKey: keys.mallorySigningPrivateJWK,
      ownDecryptionKey: keys.malloryDecryptionPrivateJWK,
      recipientPublicKeys: keys.recipientPublicKeys,
      senderPublicKeys: keys.senderPublicKeys,
    };
    malloryCodec = new KeySealedEnvelopeECCodec(malloryOptions);
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
      const limitedClientOptions: KeySealedEnvelopeECCodecOptions = {
        ownSigningKey: keys.clientSigningPrivateJWK,
        ownDecryptionKey: keys.clientDecryptionPrivateJWK,
        recipientPublicKeys: {
          keys: keys.recipientPublicKeys.keys.filter(
            (k) => k.kid !== "codecserver-1"
          ),
        },
        senderPublicKeys: keys.senderPublicKeys,
      };
      const limitedClientCodec = new KeySealedEnvelopeECCodec(
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
