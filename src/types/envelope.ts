/**
 * Represents a sealed envelope containing encrypted data and associated metadata.
 * @property {string} kid - Key ID identifying the sender's public key for signature verification
 * @property {Record<string, string>} cek - Content encryption keys for each recipient
 * @property {string} payload - The encrypted message payload
 * @property {string} signature - Digital signature of the envelope contents
 */
export type KeySealedEnvelope = {
  kid: string;
  cek: Record<string, string>;
  payload: string;
  signature: string;
};
