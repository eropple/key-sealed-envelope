import {
  type ECPublicNamedJWKS,
  type ECPrivateNamedJWK,
  type ECPublicNamedJWK,
} from "../types/index.js";
import { type KeySealedEnvelope } from "../types/index.js";

import { unsealCore } from "./core.js";

export class ECUnsealer {
  private readonly privateKey: CryptoKey;
  private readonly privateKid: string;
  private readonly senderKeys: Map<string, CryptoKey>;

  private constructor(
    privateKey: CryptoKey,
    privateKid: string,
    senderKeys: Map<string, CryptoKey>
  ) {
    this.privateKey = privateKey;
    this.privateKid = privateKid;
    this.senderKeys = senderKeys;
  }

  /**
   * Creates a new ECUnsealer instance.
   * @param privateJwk - Your EC private key for decryption
   * @param senderKeys - Array of sender EC public keys or JWKS for verification
   * @returns New ECUnsealer instance
   * @throws If keys use different curves
   */
  static async create(
    privateJwk: ECPrivateNamedJWK,
    senderKeys: ECPublicNamedJWK[] | ECPublicNamedJWKS
  ): Promise<ECUnsealer> {
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      privateJwk,
      {
        name: "ECDH",
        namedCurve: privateJwk.crv,
      },
      true,
      ["deriveKey"]
    );

    const senderJwks = Array.isArray(senderKeys) ? senderKeys : senderKeys.keys;

    const senderKeyMap = new Map();
    for (const jwk of senderJwks) {
      if (jwk.crv !== privateJwk.crv) {
        throw new Error("All keys must use the same curve");
      }

      const senderKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        {
          name: "ECDSA",
          namedCurve: jwk.crv,
        },
        true,
        ["verify"]
      );
      senderKeyMap.set(jwk.kid, senderKey);
    }

    return new ECUnsealer(privateKey, privateJwk.kid, senderKeyMap);
  }
  async unseal(envelope: KeySealedEnvelope): Promise<Uint8Array> {
    const senderKey = this.senderKeys.get(envelope.kid);
    if (!senderKey) {
      throw new Error("Unknown sender key");
    }

    return await unsealCore(envelope, this.privateKey, this.privateKid, {
      [envelope.kid]: senderKey,
    });
  }
}
