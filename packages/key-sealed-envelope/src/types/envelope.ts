/**
 * A sealed envelope containing encrypted data for multiple recipients.
 *
 * @property kid - Key ID of the sender's public key for signature verification
 * @property cek - Map of encrypted content keys per recipient
 * @property payload - Encrypted message data with IV prepended
 * @property signature - Digital signature over the envelope contents
 * @property ctx - Commitment tag ensuring all recipients decrypt to same message
 */
export type KeySealedEnvelope = {
  kid: string;
  cek: Record<string, string>;
  payload: string;
  signature: string;
  ctx: string;
};
