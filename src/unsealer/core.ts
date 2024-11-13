import { type KeySealedEnvelope } from "../types/envelope.js";

import { decryptCEK, decryptPayload, verifyEnvelope } from "./helpers.js";

/**
 * Low-level envelope unsealing function. Verifies signature and decrypts payload.
 *
 * The unsealing process:
 * 1. Verify envelope signature using sender's public key
 * 2. Decrypt recipient's CEK portion
 * 3. Use decrypted CEK to decrypt payload
 *
 * @param envelope - The sealed envelope to decrypt
 * @param recipientKey - Private key for decryption
 * @param recipientKid - Key ID of the decryption key
 * @param senderKeys - Map of sender key IDs to their public keys
 * @returns Decrypted payload as Uint8Array
 * @throws If sender unknown or signature invalid
 */
export async function unsealCore(
  envelope: KeySealedEnvelope,
  recipientKey: CryptoKey,
  recipientKid: string,
  senderKeys: Record<string, CryptoKey>
): Promise<Uint8Array> {
  const senderPublicKey = senderKeys[envelope.kid];
  if (!senderPublicKey) {
    throw new Error("Unknown sender key");
  }

  const envelopeData = {
    cek: envelope.cek,
    payload: envelope.payload,
  };

  const isValid = await verifyEnvelope(
    envelopeData,
    envelope.signature,
    senderPublicKey
  );
  if (!isValid) {
    throw new Error("Invalid envelope signature");
  }

  const encryptedCEK = envelope.cek[recipientKid];
  if (!encryptedCEK) {
    throw new Error("No CEK found for recipient");
  }

  const cek = await decryptCEK(encryptedCEK, recipientKey);
  return await decryptPayload(envelope.payload, cek);
}
