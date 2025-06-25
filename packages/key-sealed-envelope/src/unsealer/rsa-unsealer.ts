import {
  type RSAPublicNamedJWKS,
  type RSAPrivateNamedJWK,
  type RSAPublicNamedJWK,
} from "../types/index.js";
import { type KeySealedEnvelope } from "../types/index.js";

import { unsealCore } from "./core.js";

/**
 * Decrypts and verifies RSA-sealed envelopes.
 *
 * Uses RSA-OAEP with SHA-256 for decrypting the content key (your private key)
 * and RSA-PSS with SHA-256 for verifying signatures (sender public keys).
 *
 * @example
 * const unsealer = await RSAUnsealer.create(yourPrivateJWK, [senderPublicJWKs]);
 * const decrypted = await unsealer.unseal(envelope);
 */
export class RSAUnsealer {
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
   * Creates a new RSAUnsealer instance.
   *
   * @param privateJwk - Your RSA private key for decryption
   * @param senderJwks - Array of sender RSA public keys or a JWKS for verification
   * @returns New RSAUnsealer instance
   */
  static async create(
    privateJwk: RSAPrivateNamedJWK,
    senderKeys: RSAPublicNamedJWK[] | RSAPublicNamedJWKS
  ): Promise<RSAUnsealer> {
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      privateJwk,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["decrypt"]
    );

    const senderJwks = Array.isArray(senderKeys) ? senderKeys : senderKeys.keys;

    const senderKeyMap = new Map();
    for (const jwk of senderJwks) {
      const senderKey = await crypto.subtle.importKey(
        "jwk",
        jwk,
        {
          name: "RSA-PSS",
          hash: "SHA-256",
        },
        true,
        ["verify"]
      );
      senderKeyMap.set(jwk.kid, senderKey);
    }

    return new RSAUnsealer(privateKey, privateJwk.kid, senderKeyMap);
  }
  /**
   * Unseals an envelope, verifying its signature and decrypting the payload.
   *
   * @param envelope - The sealed envelope to decrypt
   * @returns Decrypted payload as Uint8Array
   * @throws If sender is unknown or signature is invalid
   */
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
