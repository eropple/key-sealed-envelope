import canonicalize from "canonicalize";

import { encryptCEKWithECDH, signEnvelopeWithEC } from "./ec.js";
import { encryptCEKWithRSA, signEnvelopeWithRSA } from "./rsa.js";

async function generateCEK(): Promise<CryptoKey> {
  return await crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );
}

async function encryptPayload(
  plaintext: string | Uint8Array,
  cek: CryptoKey
): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintextBytes =
    typeof plaintext === "string"
      ? new TextEncoder().encode(plaintext)
      : plaintext;

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    cek,
    plaintextBytes
  );

  const result = new Uint8Array(iv.length + ciphertext.byteLength);
  result.set(iv);
  result.set(new Uint8Array(ciphertext), iv.length);

  return result;
}

async function encryptCEK(
  cek: CryptoKey,
  recipientKey: CryptoKey
): Promise<Uint8Array> {
  if (recipientKey.algorithm.name === "RSA-OAEP") {
    return encryptCEKWithRSA(cek, recipientKey);
  }
  if (recipientKey.algorithm.name === "ECDH") {
    const ephemeralKey = await crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: (recipientKey.algorithm as EcKeyImportParams).namedCurve,
      },
      true,
      ["deriveKey"]
    );

    // Export ephemeral public key
    const ephemeralKeyBytes = await crypto.subtle.exportKey(
      "raw",
      ephemeralKey.publicKey
    );

    const encryptedKeyBytes = await encryptCEKWithECDH(
      cek,
      recipientKey,
      ephemeralKey
    );

    // Combine ephemeral key and encrypted data
    const result = new Uint8Array(
      ephemeralKeyBytes.byteLength + encryptedKeyBytes.byteLength
    );
    result.set(new Uint8Array(ephemeralKeyBytes));
    result.set(encryptedKeyBytes, ephemeralKeyBytes.byteLength);

    return result;
  }
  throw new Error("Unsupported key type");
}
async function signEnvelope(
  data: { cek: Record<string, string>; payload: string },
  senderKey: CryptoKey
): Promise<string> {
  const canonicalString = canonicalize(data);
  const message = new TextEncoder().encode(canonicalString);

  let signature: Uint8Array;
  if (senderKey.algorithm.name === "RSA-PSS") {
    signature = await signEnvelopeWithRSA(message, senderKey);
  } else if (senderKey.algorithm.name === "ECDSA") {
    signature = await signEnvelopeWithEC(message, senderKey);
  } else {
    throw new Error("Unsupported key type");
  }

  return Buffer.from(signature).toString("base64");
}

export { generateCEK, encryptPayload, encryptCEK, signEnvelope };
