import { describe, expect, it } from "vitest";

import { sealCore } from "../sealer/core.js";

import { unsealCore } from "./core.js";

describe("Envelope Unsealing", () => {
  describe("happy path", () => {
    it("unseals payload for intended recipient", async () => {
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

      const testMessage = "test message";
      const envelope = await sealCore(
        testMessage,
        senderKeyPair.privateKey,
        "sender1",
        { recipient1: recipientKeyPair.publicKey }
      );

      const senderKeys = { sender1: senderKeyPair.publicKey };

      const decrypted = await unsealCore(
        envelope,
        recipientKeyPair.privateKey,
        "recipient1",
        senderKeys
      );

      expect(new TextDecoder().decode(decrypted)).toBe(testMessage);
    });
  });

  describe("sad path", () => {
    it("rejects unknown sender key", async () => {
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

      const envelope = await sealCore(
        "test message",
        senderKeyPair.privateKey,
        "sender1",
        { recipient1: recipientKeyPair.publicKey }
      );

      const wrongSenderKeys = { "wrong-sender": senderKeyPair.publicKey };

      await expect(
        unsealCore(
          envelope,
          recipientKeyPair.privateKey,
          "recipient1",
          wrongSenderKeys
        )
      ).rejects.toThrow("Unknown sender key");
    });

    it("rejects tampered signature", async () => {
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

      const envelope = await sealCore(
        "test message",
        senderKeyPair.privateKey,
        "sender1",
        { recipient1: recipientKeyPair.publicKey }
      );

      const tamperedEnvelope = {
        ...envelope,
        signature: envelope.signature.replace("a", "b"),
      };

      const senderKeys = { sender1: senderKeyPair.publicKey };

      await expect(
        unsealCore(
          tamperedEnvelope,
          recipientKeyPair.privateKey,
          "recipient1",
          senderKeys
        )
      ).rejects.toThrow("Invalid envelope signature");
    });
  });

  describe("CTX commitment", () => {
    it("rejects tampered CTX tag", async () => {
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

      // Create original envelope
      const envelope = await sealCore(
        "test message",
        senderKeyPair.privateKey,
        "sender1",
        { recipient1: recipientKeyPair.publicKey }
      );

      // Create new envelope with same data but different IV/nonce
      const envelope2 = await sealCore(
        "test message",
        senderKeyPair.privateKey,
        "sender1",
        { recipient1: recipientKeyPair.publicKey }
      );

      // Use valid signature and payload from first envelope but CTX from second
      const tamperedEnvelope = {
        ...envelope,
        ctx: envelope2.ctx,
      };

      const senderKeys = { sender1: senderKeyPair.publicKey };

      await expect(
        unsealCore(
          tamperedEnvelope,
          recipientKeyPair.privateKey,
          "recipient1",
          senderKeys
        )
      ).rejects.toThrow("Invalid CTX tag");
    });

    it("rejects modified payload with valid signature", async () => {
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

      // Create original envelope
      const envelope = await sealCore(
        "test message",
        senderKeyPair.privateKey,
        "sender1",
        { recipient1: recipientKeyPair.publicKey }
      );

      // Create new envelope with different message
      const envelope2 = await sealCore(
        "different message",
        senderKeyPair.privateKey,
        "sender1",
        { recipient1: recipientKeyPair.publicKey }
      );

      // Keep envelope2's payload and signature but use envelope1's CTX
      const mixedEnvelope = {
        ...envelope2,
        ctx: envelope.ctx,
      };

      const senderKeys = { sender1: senderKeyPair.publicKey };

      await expect(
        unsealCore(
          mixedEnvelope,
          recipientKeyPair.privateKey,
          "recipient1",
          senderKeys
        )
      ).rejects.toThrow("Invalid CTX tag");
    });

    it("rejects tampered CTX tag with EC keys", async () => {
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

      // Create original envelope
      const envelope = await sealCore(
        "test message",
        senderKeyPair.privateKey,
        "sender1",
        { recipient1: recipientKeyPair.publicKey }
      );

      // Create new envelope with same data but different IV/nonce
      const envelope2 = await sealCore(
        "test message",
        senderKeyPair.privateKey,
        "sender1",
        { recipient1: recipientKeyPair.publicKey }
      );

      // Use valid signature and payload from first envelope but CTX from second
      const tamperedEnvelope = {
        ...envelope,
        ctx: envelope2.ctx,
      };

      const senderKeys = { sender1: senderKeyPair.publicKey };

      await expect(
        unsealCore(
          tamperedEnvelope,
          recipientKeyPair.privateKey,
          "recipient1",
          senderKeys
        )
      ).rejects.toThrow("Invalid CTX tag");
    });
  });
});
