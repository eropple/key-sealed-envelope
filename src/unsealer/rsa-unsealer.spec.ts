import { describe, it, expect } from "vitest";

import { RSASealer } from "../sealer/rsa-sealer.js";
import {
  type RSAPrivateNamedJWK,
  type RSAPublicNamedJWK,
} from "../types/index.js";

import { RSAUnsealer } from "./rsa-unsealer.js";

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

const recipientKeyPair = await crypto.subtle.generateKey(
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
const senderPublicJWK = await keyToPublicJWK(
  senderKeyPair.publicKey,
  "sender1"
);
const recipientPrivateJWK = await keyToPrivateJWK(
  recipientKeyPair.privateKey,
  "recipient1"
);
const recipientPublicJWK = await keyToPublicJWK(
  recipientKeyPair.publicKey,
  "recipient1"
);

describe("RSAUnsealer", () => {
  describe("creation", () => {
    it("creates instance with valid keys", async () => {
      const unsealer = await RSAUnsealer.create(recipientPrivateJWK, [
        senderPublicJWK,
      ]);
      expect(unsealer).toBeInstanceOf(RSAUnsealer);
    });

    it("creates instance with JWKS format", async () => {
      const unsealer = await RSAUnsealer.create(recipientPrivateJWK, {
        keys: [senderPublicJWK],
      });
      expect(unsealer).toBeInstanceOf(RSAUnsealer);

      const sealer = await RSASealer.create(senderPrivateJWK, [
        recipientPublicJWK,
      ]);
      const envelope = await sealer.seal("test message", ["recipient1"]);
      const decrypted = await unsealer.unseal(envelope);
      expect(new TextDecoder().decode(decrypted)).toBe("test message");
    });
  });

  describe("unsealing", () => {
    it("unseals message from known sender", async () => {
      const sealer = await RSASealer.create(senderPrivateJWK, [
        recipientPublicJWK,
      ]);
      const unsealer = await RSAUnsealer.create(recipientPrivateJWK, [
        senderPublicJWK,
      ]);

      const message = "test message";
      const envelope = await sealer.seal(message, ["recipient1"]);
      const decrypted = await unsealer.unseal(envelope);

      expect(new TextDecoder().decode(decrypted)).toBe(message);
    });

    it("rejects unknown sender", async () => {
      const unsealer = await RSAUnsealer.create(recipientPrivateJWK, []);
      const sealer = await RSASealer.create(senderPrivateJWK, [
        recipientPublicJWK,
      ]);

      const envelope = await sealer.seal("test message", ["recipient1"]);

      await expect(unsealer.unseal(envelope)).rejects.toThrow(
        "Unknown sender key"
      );
    });

    it("handles binary data", async () => {
      const sealer = await RSASealer.create(senderPrivateJWK, [
        recipientPublicJWK,
      ]);
      const unsealer = await RSAUnsealer.create(recipientPrivateJWK, [
        senderPublicJWK,
      ]);

      const binaryData = new Uint8Array([1, 2, 3, 4, 5]);
      const envelope = await sealer.seal(binaryData, ["recipient1"]);
      const decrypted = await unsealer.unseal(envelope);

      expect(new Uint8Array(decrypted)).toEqual(binaryData);
    });
  });
});
