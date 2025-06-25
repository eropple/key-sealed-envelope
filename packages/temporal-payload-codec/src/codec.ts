import {
  type ECPrivateNamedJWK,
  type ECPublicNamedJWKS,
  ECSealer,
  ECUnsealer,
  type KeySealedEnvelope,
} from "@eropple/key-sealed-envelope";
import { type Payload, type PayloadCodec } from "@temporalio/common";
import { temporal } from "@temporalio/proto";

const ENCODING = "binary/key-sealed-envelope";
const METADATA_ENCODING_KEY = "encoding";

export type KeySealedEnvelopeECCodecOptions = {
  ownSigningKey: ECPrivateNamedJWK;
  ownDecryptionKey: ECPrivateNamedJWK;
  recipientPublicKeys: ECPublicNamedJWKS;
  senderPublicKeys: ECPublicNamedJWKS;
};

export class KeySealedEnvelopeECCodec implements PayloadCodec {
  constructor(private readonly options: KeySealedEnvelopeECCodecOptions) {}

  public async encode(payloads: Payload[]): Promise<Payload[]> {
    const sealer = await ECSealer.create(
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
    const unsealer = await ECUnsealer.create(
      this.options.ownDecryptionKey,
      this.options.senderPublicKeys
    );

    return Promise.all(
      payloads.map(async (payload) => {
        // If the payload doesn't have our special encoding, pass it through.
        const encoding = payload.metadata?.[METADATA_ENCODING_KEY];
        if (!encoding || new TextDecoder().decode(encoding) !== ENCODING) {
          return payload;
        }

        // The real payload is the envelope, which is JSON-stringified in the data field.
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
