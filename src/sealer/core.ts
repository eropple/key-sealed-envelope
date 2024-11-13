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
 * 3. Encrypt CEK for each recipient
 * 4. Sign the canonical envelope
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

  const envelopeData = {
    cek: encryptedCEKs,
    payload: Buffer.from(encryptedPayload).toString("base64"),
  };

  const signature = await signEnvelope(envelopeData, senderKey);

  return {
    kid: senderKid,
    ...envelopeData,
    signature,
  };
}
