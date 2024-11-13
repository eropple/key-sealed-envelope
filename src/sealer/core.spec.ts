import { describe, it, expect } from "vitest";

import { sealCore } from "./core.js";

describe("Envelope Sealing", () => {
  describe("happy path", () => {
    it("seals payload for multiple recipients", async () => {
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

      const recipientKeys = { recipient1: recipient1KeyPair.publicKey };

      const envelope = await sealCore(
        "test message",
        senderKeyPair.privateKey,
        "sender1",
        recipientKeys
      );

      expect(envelope.kid).toBe("sender1");
      expect(envelope.cek).toHaveProperty("recipient1");
      expect(envelope.payload).toBeDefined();
      expect(envelope.signature).toBeDefined();
    });
  });

  describe("sad path", () => {
    it("rejects empty recipient list", async () => {
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

      await expect(
        sealCore("test message", senderKeyPair.privateKey, "sender1", {})
      ).rejects.toThrow("No recipients specified");
    });

    it("rejects wrong key type for sender", async () => {
      const wrongSenderKey = await crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
      );

      const recipientKey = await crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
      );

      await expect(
        sealCore("test message", wrongSenderKey.privateKey, "sender1", {
          recipient1: recipientKey.publicKey,
        })
      ).rejects.toThrow("Unsupported key type");
    });
  });
});

describe("EC key path", () => {
  it("seals with EC P-256 keys", async () => {
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

    const envelope = await sealCore(
      "test message",
      senderKeyPair.privateKey,
      "sender1",
      {
        recipient1: recipientKeyPair.publicKey,
      }
    );

    expect(envelope.kid).toBe("sender1");
    expect(envelope.cek).toHaveProperty("recipient1");
    expect(envelope.payload).toBeDefined();
    expect(envelope.signature).toBeDefined();
  });

  it("seals with EC P-384 keys", async () => {
    const senderKeyPair = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-384",
      },
      true,
      ["sign", "verify"]
    );

    const recipientKeyPair = await crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-384",
      },
      true,
      ["deriveKey"]
    );

    const envelope = await sealCore(
      "test message",
      senderKeyPair.privateKey,
      "sender1",
      {
        recipient1: recipientKeyPair.publicKey,
      }
    );

    expect(envelope.kid).toBe("sender1");
    expect(envelope.cek).toHaveProperty("recipient1");
    expect(envelope.payload).toBeDefined();
    expect(envelope.signature).toBeDefined();
  });
});

describe("Mixed key types", () => {
  it("rejects EC signing with RSA encryption", async () => {
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
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    );

    await expect(
      sealCore("test message", senderKeyPair.privateKey, "sender1", {
        recipient1: recipientKeyPair.publicKey,
      })
    ).rejects.toThrow("Mixed key types not supported");
  });

  it("rejects RSA signing with EC encryption", async () => {
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
        name: "ECDH",
        namedCurve: "P-256",
      },
      true,
      ["deriveKey"]
    );

    await expect(
      sealCore("test message", senderKeyPair.privateKey, "sender1", {
        recipient1: recipientKeyPair.publicKey,
      })
    ).rejects.toThrow("Mixed key types not supported");
  });
});
