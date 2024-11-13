export async function verifyEnvelopeWithEC(
  message: Uint8Array,
  signature: Uint8Array,
  senderPublicKey: CryptoKey
): Promise<boolean> {
  return await crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    },
    senderPublicKey,
    signature,
    message
  );
}

export async function decryptCEKWithECDH(
  encryptedCEK: Uint8Array,
  recipientKey: CryptoKey,
  senderEphemeralKey: CryptoKey
): Promise<CryptoKey> {
  const sharedSecret = await crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: senderEphemeralKey,
    },
    recipientKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["unwrapKey"]
  );

  const iv = encryptedCEK.subarray(0, 12);
  const wrappedKey = encryptedCEK.subarray(12);

  return await crypto.subtle.unwrapKey(
    "raw",
    wrappedKey,
    sharedSecret,
    {
      name: "AES-GCM",
      iv,
    },
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );
}
