import { CTX_CONSTANT_STRING } from "../constants.js";
import { type KeySealedEnvelope } from "../types/index.js";

import {
  generateCEK,
  encryptPayload,
  encryptCEK,
  signEnvelope,
} from "./helpers.js";

/**
 * Low-level envelope sealing function. Encrypts payload for multiple recipients and signs it.
 *
 * The sealing process:
 * 1. Generate random AES key (CEK)
 * 2. Encrypt payload with CEK
 * 3. Generate CTX commitment tag
 * 4. Encrypt CEK for each recipient
 * 5. Sign the canonical envelope
 *
 * @param payload - String or binary data to encrypt
 * @param senderKey - Private key for signing
 * @param senderKid - Key ID of the signing key
 * @param recipientKeys - Map of recipient key IDs to their public keys
 * @returns Sealed envelope containing encrypted data and signature
 * @throws If no recipients specified or key types are mixed
 */
export async function sealCore(
  payload: string | Uint8Array,
  senderKey: CryptoKey,
  senderKid: string,
  recipientKeys: Record<string, CryptoKey>
): Promise<KeySealedEnvelope> {
  if (Object.keys(recipientKeys).length === 0) {
    throw new Error("No recipients specified");
  }
  // Check for mixed key types
  const isRSASender = senderKey.algorithm.name === "RSA-PSS";
  const isECSender = senderKey.algorithm.name === "ECDSA";

  for (const recipientKey of Object.values(recipientKeys)) {
    const isRSARecipient = recipientKey.algorithm.name === "RSA-OAEP";
    const isECRecipient = recipientKey.algorithm.name === "ECDH";

    if ((isRSASender && isECRecipient) || (isECSender && isRSARecipient)) {
      throw new Error("Mixed key types not supported");
    }
  }
  const cek = await generateCEK();
  const encryptedPayload = await encryptPayload(payload, cek);

  const encryptedCEKs: Record<string, string> = {};
  for (const [kid, recipientKey] of Object.entries(recipientKeys)) {
    const encryptedCEK = await encryptCEK(cek, recipientKey);
    encryptedCEKs[kid] = Buffer.from(encryptedCEK).toString("base64");
  }

  // Sign the envelope before adding CTX
  const envelope = {
    kid: senderKid,
    cek: encryptedCEKs,
    payload: Buffer.from(encryptedPayload).toString("base64"),
  };

  const signature = await signEnvelope(envelope, senderKey);

  // Generate CTX after signing
  const iv = encryptedPayload.subarray(0, 12);
  const gcmTag = encryptedPayload.subarray(-16);

  const separator = new TextEncoder().encode(CTX_CONSTANT_STRING);
  const ctxInput = new Uint8Array(
    separator.length +
      iv.length +
      (encryptedPayload.length - 28) +
      gcmTag.length
  );

  let offset = 0;
  ctxInput.set(separator, offset);
  offset += separator.length;
  ctxInput.set(iv, offset);
  offset += iv.length;
  ctxInput.set(encryptedPayload.subarray(12, -16), offset);
  offset += encryptedPayload.length - 28;
  ctxInput.set(gcmTag, offset);

  const ctxTag = await crypto.subtle.digest("SHA-256", ctxInput);

  return {
    ...envelope,
    signature,
    ctx: Buffer.from(ctxTag).toString("base64"),
  };
}
