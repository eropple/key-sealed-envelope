import {
  type RSAPublicNamedJWKS,
  type RSAPrivateNamedJWK,
  type RSAPublicNamedJWK,
} from "../types/index.js";
import { type KeySealedEnvelope } from "../types/index.js";

import { sealCore } from "./core.js";

/**
 * Encrypts and signs messages using RSA keys.
 *
 * Uses RSA-PSS with SHA-256 for signing (your private key) and RSA-OAEP
 * with SHA-256 for encrypting the content key (recipient public keys).
 *
 * @example
 * const sealer = await RSASealer.create(yourPrivateJWK, [recipientPublicJWKs]);
 * const envelope = await sealer.seal("secret stuff", ["recipient1", "recipient2"]);
 */
export class RSASealer {
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
   * Creates a new RSASealer instance.
   * @param privateJwk - Your RSA private key for signing
   * @param recipientKeys - Array of recipient RSA public keys or JWKS for encryption
   * @returns New RSASealer instance
   */
  static async create(
    privateJwk: RSAPrivateNamedJWK,
    recipientKeys: RSAPublicNamedJWK[] | RSAPublicNamedJWKS
  ): Promise<RSASealer> {
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      privateJwk,
      {
        name: "RSA-PSS",
        hash: "SHA-256",
      },
      true,
      ["sign"]
    );

    const recipientJwks = Array.isArray(recipientKeys)
      ? recipientKeys
      : recipientKeys.keys;

    const recipientKeyMap = new Map();
    for (const jwk of recipientJwks) {
      const recipientKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        {
          name: "RSA-OAEP",
          hash: "SHA-256",
        },
        true,
        ["encrypt"]
      );
      recipientKeyMap.set(jwk.kid, recipientKey);
    }

    return new RSASealer(privateKey, privateJwk.kid, recipientKeyMap);
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
