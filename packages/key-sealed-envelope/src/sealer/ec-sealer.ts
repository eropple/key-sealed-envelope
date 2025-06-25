import {
  type ECPublicNamedJWKS,
  type ECPrivateNamedJWK,
  type ECPublicNamedJWK,
} from "../types/index.js";
import { type KeySealedEnvelope } from "../types/index.js";

import { sealCore } from "./core.js";

/**
 * Encrypts and signs messages using elliptic curve cryptography.
 *
 * Uses ECDSA for signing and ECDH for key exchange with per-message
 * ephemeral keys. All keys must use the same curve (P-256 or P-384).
 *
 * @example
 * const sealer = await ECSealer.create(yourPrivateJWK, [recipientPublicJWKs]);
 * const envelope = await sealer.seal("secret stuff", ["recipient1"]);
 */
export class ECSealer {
  private readonly privateKey: CryptoKey;
  private readonly privateKid: string;
  private readonly recipientKeys: Map<string, CryptoKey>;

  private constructor(
    privateKey: CryptoKey,
    privateKid: string,
    recipientKeys: Map<string, CryptoKey>
  ) {
    this.privateKey = privateKey;
    this.privateKid = privateKid;
    this.recipientKeys = recipientKeys;
  }

  /**
   * Creates a new ECSealer instance.
   * @param privateJwk - Your EC private key for signing
   * @param recipientKeys - Array of recipient EC public keys or JWKS for encryption
   * @returns New ECSealer instance
   * @throws If keys use different curves
   */
  static async create(
    privateJwk: ECPrivateNamedJWK,
    recipientKeys: ECPublicNamedJWK[] | ECPublicNamedJWKS
  ): Promise<ECSealer> {
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      privateJwk,
      {
        name: "ECDSA",
        namedCurve: privateJwk.crv,
      },
      true,
      ["sign"]
    );

    const recipientJwks = Array.isArray(recipientKeys)
      ? recipientKeys
      : recipientKeys.keys;

    const recipientKeyMap = new Map();
    for (const jwk of recipientJwks) {
      if (jwk.crv !== privateJwk.crv) {
        throw new Error("All keys must use the same curve");
      }

      const recipientKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        {
          name: "ECDH",
          namedCurve: jwk.crv,
        },
        true,
        []
      );
      recipientKeyMap.set(jwk.kid, recipientKey);
    }

    return new ECSealer(privateKey, privateJwk.kid, recipientKeyMap);
  }
  /**
   * Seals a message for specified recipients.
   *
   * @param payload - String or binary data to encrypt
   * @param recipientKids - Array of recipient key IDs to encrypt for
   * @returns Sealed envelope containing encrypted data and signature
   * @throws If any recipient kid is unknown
   */
  async seal(
    payload: string | Uint8Array,
    recipientKids: string[]
  ): Promise<KeySealedEnvelope> {
    const recipientKeyMap: Record<string, CryptoKey> = {};
    for (const kid of recipientKids) {
      const key = this.recipientKeys.get(kid);
      if (!key) {
        throw new Error(`Unknown recipient: ${kid}`);
      }
      recipientKeyMap[kid] = key;
    }

    return await sealCore(
      payload,
      this.privateKey,
      this.privateKid,
      recipientKeyMap
    );
  }
}
