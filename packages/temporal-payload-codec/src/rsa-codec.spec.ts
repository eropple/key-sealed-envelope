import {
  type RSAPrivateNamedJWK,
  type RSAPublicNamedJWK,
  type RSAPublicNamedJWKS,
} from "@eropple/key-sealed-envelope";
import { type Payload } from "@temporalio/common";
import { beforeAll, describe, expect, it } from "vitest";

import {
  KeySealedEnvelopeRSACodec,
  type KeySealedEnvelopeRSACodecOptions,
} from "./rsa-codec.js";

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
  const mallorySigningPrivateJWK = await toPrivateJWK(
    mallorySigningKeys.privateKey,
    "mallory-1"
  );
  const malloryDecryptionPrivateJWK = await toPrivateJWK(
    malloryEncryptionKeys.privateKey,
    "mallory-1"
  );

  const recipientPublicKeys: RSAPublicNamedJWKS = {
    keys: [clientEncryptionPublicJWK, workerEncryptionPublicJWK],
  };

  const senderPublicKeys: RSAPublicNamedJWKS = {
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

describe("KeySealedEnvelopeRSACodec", () => {
  let clientCodec: KeySealedEnvelopeRSACodec;
  let workerCodec: KeySealedEnvelopeRSACodec;
  let malloryCodec: KeySealedEnvelopeRSACodec; // An attacker

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
          data: undefined,
        },
      ];
      const decoded = await workerCodec.decode(encoded);
      expect(decoded[0].data).toBeUndefined();
    });
  });
});
