/**
 * Base interface for named JSON Web Keys with common properties
 */
export type BaseNamedJWK = {
  kid: string;
  kty: string;
  use?: "sig" | "enc";
  key_ops?: string[];
  alg?: string;
};

/**
 * RSA public key in JWK format with key identifier
 */
export type RSAPublicNamedJWK = BaseNamedJWK & {
  kty: "RSA";
  n: string;
  e: string;
};

/**
 * RSA private key in JWK format with key identifier
 */
export type RSAPrivateNamedJWK = RSAPublicNamedJWK & {
  d: string;
  p: string;
  q: string;
  dp: string;
  dq: string;
  qi: string;
};

/**
 * Elliptic Curve public key in JWK format with key identifier
 */
export type ECPublicNamedJWK = BaseNamedJWK & {
  kty: "EC";
  crv: string;
  x: string;
  y: string;
};

/**
 * Elliptic Curve private key in JWK format with key identifier
 */
export type ECPrivateNamedJWK = ECPublicNamedJWK & {
  d: string;
};

export type RSAPublicNamedJWKS = {
  keys: RSAPublicNamedJWK[];
};

export type RSAPrivateNamedJWKS = {
  keys: RSAPrivateNamedJWK[];
};

export type ECPublicNamedJWKS = {
  keys: ECPublicNamedJWK[];
};

export type ECPrivateNamedJWKS = {
  keys: ECPrivateNamedJWK[];
};
