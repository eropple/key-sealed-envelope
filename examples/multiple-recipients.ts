import {
  type ECPrivateNamedJWK,
  type ECPublicNamedJWK,
  type ECPublicNamedJWKS,
  ECSealer,
  ECUnsealer,
} from "../src/index.ts";

async function multipleRecipients() {
  // Generate signing keys for senders (ECDSA)
  const generateSigningKeyPair = () =>
    crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"]
    );

  // Generate encryption keys for recipients (ECDH)
  const generateEncryptionKeyPair = () =>
    crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      true,
      ["deriveKey"]
    );

  // Generate all key pairs
  const [
    aliceSigningKeys,
    bobSigningKeys,
    carolEncryptionKeys,
    daveEncryptionKeys,
    aliceEncryptionKeys,
  ] = await Promise.all([
    generateSigningKeyPair(),
    generateSigningKeyPair(),
    generateEncryptionKeyPair(),
    generateEncryptionKeyPair(),
    generateEncryptionKeyPair(),
  ]);

  // Create private JWKs for senders (signing keys)
  const alicePrivateJWK: ECPrivateNamedJWK = {
    ...((await crypto.subtle.exportKey(
      "jwk",
      aliceSigningKeys.privateKey
    )) as ECPrivateNamedJWK),
    kid: "alice-1",
    kty: "EC",
    crv: "P-256",
  };

  const bobPrivateJWK: ECPrivateNamedJWK = {
    ...((await crypto.subtle.exportKey(
      "jwk",
      bobSigningKeys.privateKey
    )) as ECPrivateNamedJWK),
    kid: "bob-1",
    kty: "EC",
    crv: "P-256",
  };

  // Create public JWKS for recipients (encryption keys)
  const recipientJWKS: ECPublicNamedJWKS = {
    keys: [
      {
        ...((await crypto.subtle.exportKey(
          "jwk",
          carolEncryptionKeys.publicKey
        )) as ECPublicNamedJWK),
        kid: "carol-1",
        kty: "EC",
        crv: "P-256",
      },
      {
        ...((await crypto.subtle.exportKey(
          "jwk",
          daveEncryptionKeys.publicKey
        )) as ECPublicNamedJWK),
        kid: "dave-1",
        kty: "EC",
        crv: "P-256",
      },
      {
        ...((await crypto.subtle.exportKey(
          "jwk",
          aliceEncryptionKeys.publicKey
        )) as ECPublicNamedJWK),
        kid: "alice-1",
        kty: "EC",
        crv: "P-256",
      },
    ],
  };

  // Create public JWKS for senders (verification keys)
  const senderJWKS: ECPublicNamedJWKS = {
    keys: [
      {
        ...((await crypto.subtle.exportKey(
          "jwk",
          aliceSigningKeys.publicKey
        )) as ECPublicNamedJWK),
        kid: "alice-1",
        kty: "EC",
        crv: "P-256",
      },
      {
        ...((await crypto.subtle.exportKey(
          "jwk",
          bobSigningKeys.publicKey
        )) as ECPublicNamedJWK),
        kid: "bob-1",
        kty: "EC",
        crv: "P-256",
      },
    ],
  };

  // Alice sends to Carol and Dave
  const aliceSealer = await ECSealer.create(alicePrivateJWK, recipientJWKS);
  const aliceMessage = await aliceSealer.seal("Secret message from Alice", [
    "carol-1",
    "dave-1",
  ]);

  // Bob sends to Alice and Dave
  const bobSealer = await ECSealer.create(bobPrivateJWK, recipientJWKS);
  const bobMessage = await bobSealer.seal("Secret message from Bob", [
    "alice-1",
    "dave-1",
  ]);

  // Carol can unseal messages from either Alice or Bob
  const carolPrivateJWK: ECPrivateNamedJWK = {
    ...((await crypto.subtle.exportKey(
      "jwk",
      carolEncryptionKeys.privateKey
    )) as ECPrivateNamedJWK),
    kid: "carol-1",
    kty: "EC",
    crv: "P-256",
  };
  const carolUnsealer = await ECUnsealer.create(carolPrivateJWK, senderJWKS);
  console.log(
    "I'm Carol now",
    aliceMessage,
    new TextDecoder().decode(await carolUnsealer.unseal(aliceMessage))
  );

  // Dave can do the same
  const davePrivateJWK: ECPrivateNamedJWK = {
    ...((await crypto.subtle.exportKey(
      "jwk",
      daveEncryptionKeys.privateKey
    )) as ECPrivateNamedJWK),
    kid: "dave-1",
    kty: "EC",
    crv: "P-256",
  };
  const daveUnsealer = await ECUnsealer.create(davePrivateJWK, senderJWKS);
  console.log(
    "I'm Dave now",
    bobMessage,
    new TextDecoder().decode(await daveUnsealer.unseal(bobMessage))
  );
}

multipleRecipients().catch(console.error);
