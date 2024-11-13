async function verifyEnvelopeWithRSA(
  message: Uint8Array,
  signature: Uint8Array,
  senderPublicKey: CryptoKey
): Promise<boolean> {
  return await crypto.subtle.verify(
    {
      name: "RSA-PSS",
      saltLength: 32,
    },
    senderPublicKey,
    signature,
    message
  );
}

async function decryptCEKWithRSA(
  encryptedCEK: Uint8Array,
  recipientKey: CryptoKey
): Promise<CryptoKey> {
  const decryptedCEK = await crypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    recipientKey,
    encryptedCEK
  );

  return await crypto.subtle.importKey("raw", decryptedCEK, "AES-GCM", true, [
    "encrypt",
    "decrypt",
  ]);
}

export { verifyEnvelopeWithRSA, decryptCEKWithRSA };
