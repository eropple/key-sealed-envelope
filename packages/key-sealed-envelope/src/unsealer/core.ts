import { CTX_CONSTANT_STRING } from "../constants.js";
import { type KeySealedEnvelope } from "../types/envelope.js";
import { areUint8ArraysEqual, base64ToUint8Array } from "../utils.js";

import { decryptCEK, verifyEnvelope } from "./helpers.js";

/**
 * Low-level envelope unsealing function. Verifies signature and decrypts payload.
 *
 * The unsealing process:
 * 1. Verify envelope signature using sender's public key
 * 2. Decrypt recipient's CEK portion
 * 3. Verify CTX commitment tag
 * 4. Use decrypted CEK to decrypt payload
 *
 * @param envelope - The sealed envelope to decrypt
 * @param recipientKey - Private key for decryption
 * @param recipientKid - Key ID of the decryption key
 * @param senderKeys - Map of sender key IDs to their public keys
 * @returns Decrypted payload as Uint8Array
 * @throws If sender unknown, signature invalid, or CTX verification fails
 */
export async function unsealCore(
  envelope: KeySealedEnvelope,
  recipientKey: CryptoKey,
  recipientKid: string,
  senderKeys: Record<string, CryptoKey>
): Promise<Uint8Array> {
  const senderKey = senderKeys[envelope.kid];
  if (!senderKey) {
    throw new Error("Unknown sender key");
  }

  // Verify signature first
  const signatureValid = await verifyEnvelope(
    {
      kid: envelope.kid,
      cek: envelope.cek,
      payload: envelope.payload,
    },
    envelope.signature,
    senderKey
  );

  if (!signatureValid) {
    throw new Error("Invalid envelope signature");
  }

  // Decrypt the CEK
  const cek = await decryptCEK(envelope.cek[recipientKid], recipientKey);

  // Extract IV and encrypted data
  const encrypted = base64ToUint8Array(envelope.payload);
  const iv = encrypted.subarray(0, 12);
  const gcmTag = encrypted.subarray(-16);

  // Build CTX input with domain separator
  const separator = new TextEncoder().encode(CTX_CONSTANT_STRING);
  const ctxInput = new Uint8Array(
    separator.length + iv.length + (encrypted.length - 28) + gcmTag.length
  );

  let offset = 0;
  ctxInput.set(separator, offset);
  offset += separator.length;
  ctxInput.set(iv, offset);
  offset += iv.length;
  ctxInput.set(encrypted.subarray(12, -16), offset);
  offset += encrypted.length - 28;
  ctxInput.set(gcmTag, offset);

  const computedCtx = await crypto.subtle.digest("SHA-256", ctxInput);

  // Verify CTX tag
  const expectedCtx = base64ToUint8Array(envelope.ctx);
  if (!areUint8ArraysEqual(new Uint8Array(computedCtx), expectedCtx)) {
    throw new Error("Invalid CTX tag");
  }

  // Decrypt payload
  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
    },
    cek,
    encrypted.subarray(12)
  );

  return new Uint8Array(decrypted);
}
