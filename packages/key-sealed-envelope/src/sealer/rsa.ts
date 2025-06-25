/**
 * Encrypts a content encryption key using RSA-OAEP
 * @param cek - Content encryption key to protect
 * @param recipientKey - Recipient's RSA public key
 * @returns Encrypted key bytes
 */
export async function encryptCEKWithRSA(
  cek: CryptoKey,
  recipientKey: CryptoKey
): Promise<Uint8Array> {
  const exportedCEK = await crypto.subtle.exportKey("raw", cek);
  return new Uint8Array(
    await crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipientKey, exportedCEK)
  );
}

/**
 * Signs envelope contents using RSA-PSS
 * @param message - Message bytes to sign
 * @param senderKey - Private key for signing
 * @returns Digital signature as bytes
 */
export async function signEnvelopeWithRSA(
  message: Uint8Array,
  senderKey: CryptoKey
): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.sign(
      {
        name: "RSA-PSS",
        saltLength: 32,
      },
      senderKey,
      message
    )
  );
}
