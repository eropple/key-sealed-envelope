import { describe, it, expect } from "vitest";

import { ECSealer } from "../sealer/ec-sealer.js";
import {
  type ECPrivateNamedJWK,
  type ECPublicNamedJWK,
} from "../types/index.js";

import { ECUnsealer } from "./ec-unsealer.js";

// Generate test keys
const senderKeyPair = await crypto.subtle.generateKey(
  {
    name: "ECDSA",
    namedCurve: "P-256",
  },
  true,
  ["sign", "verify"]
);

const recipientKeyPair = await crypto.subtle.generateKey(
  {
    name: "ECDH",
    namedCurve: "P-256",
  },
  true,
  ["deriveKey"]
);

async function keyToPrivateJWK(
  key: CryptoKey,
  kid: string
): Promise<ECPrivateNamedJWK> {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  return { ...jwk, kid } as ECPrivateNamedJWK;
}

async function keyToPublicJWK(
  key: CryptoKey,
  kid: string
): Promise<ECPublicNamedJWK> {
  const jwk = await crypto.subtle.exportKey("jwk", key);
  return { ...jwk, kid } as ECPublicNamedJWK;
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

describe("ECUnsealer", () => {
  describe("creation", () => {
    it("creates instance with valid keys", async () => {
      const unsealer = await ECUnsealer.create(recipientPrivateJWK, [
        senderPublicJWK,
      ]);
      expect(unsealer).toBeInstanceOf(ECUnsealer);
    });

    it("creates instance with JWKS format", async () => {
      const unsealer = await ECUnsealer.create(recipientPrivateJWK, {
        keys: [senderPublicJWK],
      });
      expect(unsealer).toBeInstanceOf(ECUnsealer);

      const sealer = await ECSealer.create(senderPrivateJWK, [
        recipientPublicJWK,
      ]);
      const envelope = await sealer.seal("test message", ["recipient1"]);
      const decrypted = await unsealer.unseal(envelope);
      expect(new TextDecoder().decode(decrypted)).toBe("test message");
    });

    it("rejects mismatched curves", async () => {
      const p384KeyPair = await crypto.subtle.generateKey(
        {
          name: "ECDSA",
          namedCurve: "P-384",
        },
        true,
        ["sign", "verify"]
      );
      const p384JWK = await keyToPublicJWK(p384KeyPair.publicKey, "p384");

      await expect(
        ECUnsealer.create(recipientPrivateJWK, [p384JWK])
      ).rejects.toThrow("All keys must use the same curve");
    });
  });

  describe("unsealing", () => {
    it("unseals message from known sender", async () => {
      const sealer = await ECSealer.create(senderPrivateJWK, [
        recipientPublicJWK,
      ]);
      const unsealer = await ECUnsealer.create(recipientPrivateJWK, [
        senderPublicJWK,
      ]);

      const message = "test message";
      const envelope = await sealer.seal(message, ["recipient1"]);
      const decrypted = await unsealer.unseal(envelope);

      expect(new TextDecoder().decode(decrypted)).toBe(message);
    });

    it("rejects unknown sender", async () => {
      const unsealer = await ECUnsealer.create(recipientPrivateJWK, []);
      const sealer = await ECSealer.create(senderPrivateJWK, [
        recipientPublicJWK,
      ]);

      const envelope = await sealer.seal("test message", ["recipient1"]);

      await expect(unsealer.unseal(envelope)).rejects.toThrow(
        "Unknown sender key"
      );
    });

    it("handles binary data", async () => {
      const sealer = await ECSealer.create(senderPrivateJWK, [
        recipientPublicJWK,
      ]);
      const unsealer = await ECUnsealer.create(recipientPrivateJWK, [
        senderPublicJWK,
      ]);

      const binaryData = new Uint8Array([1, 2, 3, 4, 5]);
      const envelope = await sealer.seal(binaryData, ["recipient1"]);
      const decrypted = await unsealer.unseal(envelope);

      expect(new Uint8Array(decrypted)).toEqual(binaryData);
    });
  });
});
