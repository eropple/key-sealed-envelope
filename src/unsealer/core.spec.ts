import { describe, it, expect } from "vitest";

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
});
