import {
  type RSAPrivateNamedJWK,
  type RSAPublicNamedJWK,
  type RSAPublicNamedJWKS,
  RSASealer,
  RSAUnsealer,
} from "../src/index.ts";

async function quickstart() {
  // First, we need some keys. In production you'd load these from secure storage.
  // Here we'll generate them for demonstration.
  const aliceKeyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );

  const bobKeyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  // Convert keys to JWK format with key IDs
  const alicePrivateJWK = {
    ...(await crypto.subtle.exportKey("jwk", aliceKeyPair.privateKey)),
    kid: "alice-1",
    kty: "RSA", // we need a little more explicit information about the key
  } as RSAPrivateNamedJWK;

  // Create a JWKS for Bob's public key
  const bobPublicJWKS: RSAPublicNamedJWKS = {
    keys: [
      {
        ...((await crypto.subtle.exportKey(
          "jwk",
          bobKeyPair.publicKey
        )) as RSAPublicNamedJWK),
        kid: "bob-1",
        kty: "RSA", // we need a little more explicit information about the key
      },
    ],
  };

  // Alice wants to send an encrypted message to Bob
  const sealer = await RSASealer.create(
    alicePrivateJWK, // Alice's private key for signing
    bobPublicJWKS // Bob's public JWKS for encryption
  );

  const envelope = await sealer.seal(
    "Hello Bob! This message is encrypted just for you.",
    ["bob-1"] // Recipient key IDs
  );

  // On Bob's side, he needs Alice's public JWKS to verify signatures
  const alicePublicJWKS: RSAPublicNamedJWKS = {
    keys: [
      {
        ...((await crypto.subtle.exportKey(
          "jwk",
          aliceKeyPair.publicKey
        )) as RSAPublicNamedJWK),
        kid: "alice-1",
        kty: "RSA", // we need a little more explicit information about the key
        use: "sig", // and WebCrypto demands `use` to be set
      },
    ],
  };
  const bobPrivateJWK = {
    ...(await crypto.subtle.exportKey("jwk", bobKeyPair.privateKey)),
    kid: "bob-1",
  } as RSAPrivateNamedJWK;

  const unsealer = await RSAUnsealer.create(
    bobPrivateJWK, // Bob's private key for decryption
    alicePublicJWKS // Alice's public JWKS for verification
  );

  const decrypted = await unsealer.unseal(envelope);
  console.log(new TextDecoder().decode(decrypted));

  // The library also supports:
  // - Multiple recipients per message
  // - EC keys (see ECSealer/ECUnsealer)
  // - Binary payloads
}

quickstart().catch(console.error);
