import {
  type RSAPrivateNamedJWK,
  type RSAPublicNamedJWKS,
  RSASealer,
  RSAUnsealer,
  type KeySealedEnvelope,
} from "@eropple/key-sealed-envelope";
import { type Payload, type PayloadCodec } from "@temporalio/common";
import { temporal } from "@temporalio/proto";

const ENCODING = "binary/key-sealed-envelope";
const METADATA_ENCODING_KEY = "encoding";

/**
 * Options for creating a {@link KeySealedEnvelopeRSACodec}.
 */
export type KeySealedEnvelopeRSACodecOptions = {
  /**
   * The private `RSA-PSS` key of the current entity (e.g., a specific Client or Worker),
   * used to sign all outgoing payloads.
   */
  ownSigningKey: RSAPrivateNamedJWK;
  /**
   * The private `RSA-OAEP` key of the current entity, used to decrypt incoming
   * payloads.
   */
  ownDecryptionKey: RSAPrivateNamedJWK;
  /**
   * A JWKS containing the public `RSA-OAEP` keys of all possible recipients. This
   * is used during the `encode` phase to encrypt the content encryption key (CEK)
   * for each intended recipient.
   */
  recipientPublicKeys: RSAPublicNamedJWKS;
  /**
   * A JWKS containing the public `RSA-PSS` keys of all possible senders. This
   * is used during the `decode` phase to verify the signature of the envelope.
   */
  senderPublicKeys: RSAPublicNamedJWKS;
};

/**
 * A Temporal {@link PayloadCodec} that uses `@eropple/key-sealed-envelope` with
 * RSA keys to encrypt and decrypt payloads.
 *
 * This codec encrypts each Temporal `Payload` within a signed, sealed envelope,
 * ensuring that only intended recipients can decrypt it and that the sender's
 * identity can be verified.
 */
export class KeySealedEnvelopeRSACodec implements PayloadCodec {
  /**
   * Creates an instance of the RSA-based payload codec.
   * @param options The configuration options, including all necessary cryptographic keys.
   */
  constructor(private readonly options: KeySealedEnvelopeRSACodecOptions) {}

  public async encode(payloads: Payload[]): Promise<Payload[]> {
    const sealer = await RSASealer.create(
      this.options.ownSigningKey,
      this.options.recipientPublicKeys
    );
    const recipientKids = this.options.recipientPublicKeys.keys.map(
      (key) => key.kid
    );

    return Promise.all(
      payloads.map(async (payload) => {
        const encodedPayload =
          temporal.api.common.v1.Payload.encode(payload).finish();
        const envelope = await sealer.seal(encodedPayload, recipientKids);

        return {
          metadata: {
            [METADATA_ENCODING_KEY]: new TextEncoder().encode(ENCODING),
          },
          data: new TextEncoder().encode(JSON.stringify(envelope)),
        };
      })
    );
  }

  public async decode(payloads: Payload[]): Promise<Payload[]> {
    const unsealer = await RSAUnsealer.create(
      this.options.ownDecryptionKey,
      this.options.senderPublicKeys
    );

    return Promise.all(
      payloads.map(async (payload) => {
        const encoding = payload.metadata?.[METADATA_ENCODING_KEY];
        if (!encoding || new TextDecoder().decode(encoding) !== ENCODING) {
          return payload;
        }

        if (!payload.data) {
          return payload;
        }

        const envelope: KeySealedEnvelope = JSON.parse(
          new TextDecoder().decode(payload.data)
        );

        const decryptedPayload = await unsealer.unseal(envelope);

        return temporal.api.common.v1.Payload.decode(decryptedPayload);
      })
    );
  }
}
