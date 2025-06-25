import { describe, it, expect } from "vitest";

import {
  type ECPrivateNamedJWK,
  type ECPublicNamedJWK,
} from "../types/index.js";

import { ECSealer } from "./ec-sealer.js";

// Generate test keys
const senderKeyPair = await crypto.subtle.generateKey(
  {
    name: "ECDSA",
    namedCurve: "P-256",
  },
  true,
  ["sign", "verify"]
);

const recipient1KeyPair = await crypto.subtle.generateKey(
  {
    name: "ECDH",
    namedCurve: "P-256",
  },
  true,
  ["deriveKey"]
);

const recipient2KeyPair = await crypto.subtle.generateKey(
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
const recipient1PublicJWK = await keyToPublicJWK(
  recipient1KeyPair.publicKey,
  "recipient1"
);
const recipient2PublicJWK = await keyToPublicJWK(
  recipient2KeyPair.publicKey,
  "recipient2"
);

describe("ECSealer", () => {
  describe("creation", () => {
    it("creates instance with valid keys", async () => {
      const sealer = await ECSealer.create(senderPrivateJWK, [
        recipient1PublicJWK,
        recipient2PublicJWK,
      ]);
      expect(sealer).toBeInstanceOf(ECSealer);
    });

    it("creates instance with JWKS format", async () => {
      const sealer = await ECSealer.create(senderPrivateJWK, {
        keys: [recipient1PublicJWK, recipient2PublicJWK],
      });
      expect(sealer).toBeInstanceOf(ECSealer);

      const envelope = await sealer.seal("test message", [
        "recipient1",
        "recipient2",
      ]);
      expect(envelope.cek).toHaveProperty("recipient1");
      expect(envelope.cek).toHaveProperty("recipient2");
    });

    it("rejects mismatched curves", async () => {
      const p384KeyPair = await crypto.subtle.generateKey(
        {
          name: "ECDH",
          namedCurve: "P-384",
        },
        true,
        ["deriveKey"]
      );
      const p384JWK = await keyToPublicJWK(p384KeyPair.publicKey, "p384");

      await expect(
        ECSealer.create(senderPrivateJWK, [p384JWK])
      ).rejects.toThrow("All keys must use the same curve");
    });
  });

  describe("sealing", () => {
    it("seals for multiple recipients", async () => {
      const sealer = await ECSealer.create(senderPrivateJWK, [
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
      const sealer = await ECSealer.create(senderPrivateJWK, [
        recipient1PublicJWK,
      ]);

      await expect(sealer.seal("test message", ["unknown1"])).rejects.toThrow(
        "Unknown recipient: unknown1"
      );
    });

    it("handles binary data", async () => {
      const sealer = await ECSealer.create(senderPrivateJWK, [
        recipient1PublicJWK,
      ]);

      const binaryData = new Uint8Array([1, 2, 3, 4, 5]);
      const envelope = await sealer.seal(binaryData, ["recipient1"]);

      expect(envelope.payload).toBeDefined();
      expect(envelope.cek).toHaveProperty("recipient1");
    });
  });
});
