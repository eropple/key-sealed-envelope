import {
  type ECPrivateNamedJWK,
  type ECPublicNamedJWK,
  type ECPublicNamedJWKS,
} from "@eropple/key-sealed-envelope";
import { type Payload } from "@temporalio/common";
import { beforeAll, describe, expect, it } from "vitest";

import {
  KeySealedEnvelopeECCodec,
  type KeySealedEnvelopeECCodecOptions,
} from "./ec-codec.js";

// --- Key Generation ---
// In a real application, these would be loaded securely.

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
    mallorySigningKeys,
    malloryEncryptionKeys,
  ] = await Promise.all([
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
  const mallorySigningPrivateJWK = await toPrivateJWK(
    mallorySigningKeys.privateKey,
    "mallory-1"
  );
  const malloryDecryptionPrivateJWK = await toPrivateJWK(
    malloryEncryptionKeys.privateKey,
    "mallory-1"
  );

  const recipientPublicKeys: ECPublicNamedJWKS = {
    keys: [clientEncryptionPublicJWK, workerEncryptionPublicJWK],
  };

  const senderPublicKeys: ECPublicNamedJWKS = {
    keys: [clientSigningPublicJWK, workerSigningPublicJWK],
  };

  return {
    clientSigningPrivateJWK,
    clientDecryptionPrivateJWK,
    workerSigningPrivateJWK,
    workerDecryptionPrivateJWK,
    mallorySigningPrivateJWK,
    malloryDecryptionPrivateJWK,
    recipientPublicKeys,
    senderPublicKeys,
  };
}

// --- Tests ---

describe("KeySealedEnvelopeECCodec", () => {
  let clientCodec: KeySealedEnvelopeECCodec;
  let workerCodec: KeySealedEnvelopeECCodec;
  let malloryCodec: KeySealedEnvelopeECCodec; // An attacker

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
    it("should correctly encode and decode a payload from client to worker", async () => {
      const originalPayload = createSamplePayload("hello worker");
      const encoded = await clientCodec.encode([originalPayload]);
      const decoded = await workerCodec.decode(encoded);
      expect(decoded[0]).toEqual(originalPayload);
    });

    it("should correctly encode and decode a payload from worker to client", async () => {
      const originalPayload = createSamplePayload("hello client");
      const encoded = await workerCodec.encode([originalPayload]);
      const decoded = await clientCodec.decode(encoded);
      expect(decoded[0]).toEqual(originalPayload);
    });
  });

  describe("sad path", () => {
    it("should pass through a payload that is not encoded with the codec", async () => {
      const originalPayload = createSamplePayload("I am not encoded");
      const decoded = await workerCodec.decode([originalPayload]);
      expect(decoded[0]).toEqual(originalPayload);
    });

    it("should throw an error if a non-recipient tries to decode", async () => {
      const originalPayload = createSamplePayload("super secret message");
      const encoded = await clientCodec.encode([originalPayload]);
      await expect(malloryCodec.decode(encoded)).rejects.toThrow();
    });

    it("should throw an error if the envelope is tampered with", async () => {
      const originalPayload = createSamplePayload("do not tamper");
      const encoded = await clientCodec.encode([originalPayload]);

      // Tamper with the data
      const tamperedData = new Uint8Array(encoded[0].data!);
      tamperedData[10] = (tamperedData[10] + 1) % 256;
      encoded[0].data = tamperedData;

      await expect(workerCodec.decode(encoded)).rejects.toThrow();
    });

    it("should throw an error if the payload data is missing", async () => {
      const encoded: Payload[] = [
        {
          metadata: {
            encoding: new TextEncoder().encode("binary/key-sealed-envelope"),
          },
          data: undefined, // Missing data
        },
      ];
      const decoded = await workerCodec.decode(encoded);
      expect(decoded[0].data).toBeUndefined();
    });
  });
});
