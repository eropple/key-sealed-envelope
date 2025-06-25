import canonicalize from "canonicalize";

import { base64ToUint8Array } from "../utils.js";

import { verifyEnvelopeWithEC, decryptCEKWithECDH } from "./ec.js";
import { verifyEnvelopeWithRSA, decryptCEKWithRSA } from "./rsa.js";

export async function verifyEnvelope(
  data: { kid: string; cek: Record<string, string>; payload: string },
  signature: string,
  senderPublicKey: CryptoKey
): Promise<boolean> {
  const canonicalString = canonicalize(data);
  const message = new TextEncoder().encode(canonicalString);
  const signatureBytes = base64ToUint8Array(signature);

  if (senderPublicKey.algorithm.name === "RSA-PSS") {
    return verifyEnvelopeWithRSA(message, signatureBytes, senderPublicKey);
  }
  if (senderPublicKey.algorithm.name === "ECDSA") {
    return verifyEnvelopeWithEC(message, signatureBytes, senderPublicKey);
  }
  throw new Error("Unsupported key type");
}
export async function decryptCEK(
  encryptedCEK: string,
  recipientKey: CryptoKey
): Promise<CryptoKey> {
  const encryptedBytes = base64ToUint8Array(encryptedCEK);

  if (recipientKey.algorithm.name === "RSA-OAEP") {
    return decryptCEKWithRSA(encryptedBytes, recipientKey);
  }
  if (recipientKey.algorithm.name === "ECDH") {
    // Extract ephemeral key and encrypted data
    const ephemeralKeyBytes = encryptedBytes.subarray(0, 65); // P-256 public key is 65 bytes
    const encryptedKeyBytes = encryptedBytes.subarray(65);

    const ephemeralKey = await crypto.subtle.importKey(
      "raw",
      ephemeralKeyBytes,
      {
        name: "ECDH",
        namedCurve: (recipientKey.algorithm as EcKeyImportParams).namedCurve,
      },
      true,
      []
    );

    return decryptCEKWithECDH(encryptedKeyBytes, recipientKey, ephemeralKey);
  }
  throw new Error("Unsupported key type");
}

export async function decryptPayload(
  encryptedPayload: string,
  cek: CryptoKey
): Promise<Uint8Array> {
  const encryptedBytes = base64ToUint8Array(encryptedPayload);
  const iv = encryptedBytes.subarray(0, 12);
  const ciphertext = encryptedBytes.subarray(12);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
    },
    cek,
    ciphertext
  );

  return new Uint8Array(decrypted);
}
