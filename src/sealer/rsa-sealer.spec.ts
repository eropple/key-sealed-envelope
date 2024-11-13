import { describe, it, expect } from "vitest";

import {
  type RSAPrivateNamedJWK,
  type RSAPublicNamedJWK,
} from "../types/index.js";

import { RSASealer } from "./rsa-sealer.js";

// Generate test keys
const senderKeyPair = await crypto.subtle.generateKey(
  {
    name: "RSA-PSS",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  },
  true,
  ["sign", "verify"]
);

const recipient1KeyPair = await crypto.subtle.generateKey(
  {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  },
  true,
  ["encrypt", "decrypt"]
);

const recipient2KeyPair = await crypto.subtle.generateKey(
  {
    name: "RSA-OAEP",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  },
  true,
  ["encrypt", "decrypt"]
);

async function keyToPrivateJWK(
  key: CryptoKey,
  kid: string
): Promise<RSAPrivateNamedJWK> {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  return { ...jwk, kid } as RSAPrivateNamedJWK;
}

async function keyToPublicJWK(
  key: CryptoKey,
  kid: string
): Promise<RSAPublicNamedJWK> {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  return { ...jwk, kid } as RSAPublicNamedJWK;
}

// Convert keys to JWKs
const senderPrivateJWK = await keyToPrivateJWK(
  senderKeyPair.privateKey,
  "sender1"
);
const recipient1PublicJWK = await keyToPublicJWK(
  recipient1KeyPair.publicKey,
  "recipient1"
);
const recipient2PublicJWK = await keyToPublicJWK(
  recipient2KeyPair.publicKey,
  "recipient2"
);

describe("RSASealer", () => {
  describe("creation", () => {
    it("creates instance with valid keys", async () => {
      const sealer = await RSASealer.create(senderPrivateJWK, [
        recipient1PublicJWK,
        recipient2PublicJWK,
      ]);
      expect(sealer).toBeInstanceOf(RSASealer);
    });

    it("creates instance with JWKS format", async () => {
      const sealer = await RSASealer.create(senderPrivateJWK, {
        keys: [recipient1PublicJWK, recipient2PublicJWK],
      });
      expect(sealer).toBeInstanceOf(RSASealer);

      const envelope = await sealer.seal("test message", [
        "recipient1",
        "recipient2",
      ]);
      expect(envelope.cek).toHaveProperty("recipient1");
      expect(envelope.cek).toHaveProperty("recipient2");
    });
  });

  describe("sealing", () => {
    it("seals for multiple recipients", async () => {
      const sealer = await RSASealer.create(senderPrivateJWK, [
        recipient1PublicJWK,
        recipient2PublicJWK,
      ]);

      const envelope = await sealer.seal("test message", [
        "recipient1",
        "recipient2",
      ]);

      expect(envelope.kid).toBe("sender1");
      expect(envelope.cek).toHaveProperty("recipient1");
      expect(envelope.cek).toHaveProperty("recipient2");
      expect(envelope.payload).toBeDefined();
      expect(envelope.signature).toBeDefined();
    });

    it("rejects unknown recipient", async () => {
      const sealer = await RSASealer.create(senderPrivateJWK, [
        recipient1PublicJWK,
      ]);

      await expect(sealer.seal("test message", ["unknown1"])).rejects.toThrow(
        "Unknown recipient: unknown1"
      );
    });

    it("handles binary data", async () => {
      const sealer = await RSASealer.create(senderPrivateJWK, [
        recipient1PublicJWK,
      ]);

      const binaryData = new Uint8Array([1, 2, 3, 4, 5]);
      const envelope = await sealer.seal(binaryData, ["recipient1"]);

      expect(envelope.payload).toBeDefined();
      expect(envelope.cek).toHaveProperty("recipient1");
    });
  });
});
