/**
 * Encrypts a content encryption key using ECDH key agreement
 * @param cek - Content encryption key to protect
 * @param recipientKey - Recipient's public key for ECDH
 * @param ephemeralKey - One-time key pair for this encryption
 * @returns Encrypted key material with IV prepended
 */
export async function encryptCEKWithECDH(
  cek: CryptoKey,
  recipientKey: CryptoKey,
  ephemeralKey: CryptoKeyPair
): Promise<Uint8Array> {
  const sharedSecret = await crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: recipientKey,
    },
    ephemeralKey.privateKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["wrapKey"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.wrapKey("raw", cek, sharedSecret, {
    name: "AES-GCM",
    iv,
  });

  // Combine IV and wrapped key
  const result = new Uint8Array(iv.length + wrapped.byteLength);
  result.set(iv);
  result.set(new Uint8Array(wrapped), iv.length);
  return result;
}

/**
 * Signs envelope contents using ECDSA
 * @param message - Message bytes to sign
 * @param senderKey - Private key for signing
 * @returns Digital signature as bytes
 */
export async function signEnvelopeWithEC(
  message: Uint8Array,
  senderKey: CryptoKey
): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: { name: "SHA-256" },
      },
      senderKey,
      message
    )
  );
}
