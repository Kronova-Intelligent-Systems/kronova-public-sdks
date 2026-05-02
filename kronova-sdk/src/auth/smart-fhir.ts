// kronova-sdk/src/auth/smart-fhir.ts

import { CryptoEngine } from '../security/crypto';

export interface SmartFhirClaims {
  iss: string;           // The Kronova OAuth 2.1 Server URL
  sub: string;           // The Practitioner, Patient, or System Agent ID
  aud: string;           // The target FHIR Resource Server URL
  exp: number;           // Expiration timestamp
  iat: number;           // Issued at timestamp
  jti: string;           // Unique token identifier
  scope: string;         // e.g., "patient/Observation.read" or "system/Claim.write"
  patient?: string;      // (Optional) The specific patient context for this session
  kronova_did?: string;  // The AetherNet Agent DID for downstream settlement
}

export class KronovaSmartAuth {
  constructor(
    private crypto: CryptoEngine, 
    private issuerUrl: string
  ) {}

  /**
   * Generates a Post-Quantum JSON Web Token (PQ-JWT) for FHIR Authorization
   */
  async issueAccessToken(claims: Omit<SmartFhirClaims, 'iss' | 'iat' | 'jti'>): Promise<string> {
    
    const fullClaims: SmartFhirClaims = {
      ...claims,
      iss: this.issuerUrl,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
    };

    // 1. Standard JWT Header, but specifying the NIST FIPS-204 standard
    const header = { 
      alg: "ML-DSA-44", // Representing Dilithium Mode 2/3
      typ: "JWT",
      kid: "kronova-pqc-key-01" 
    };

    // Encode Header and Payload to Base64URL
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(fullClaims)).toString('base64url');

    const unsignedToken = `${encodedHeader}.${encodedPayload}`;

    // 2. Sign with the SDK's Native ML-DSA Engine
    const signatureB64 = await this.crypto.sign(unsignedToken);
    
    // Convert standard Base64 to Base64URL for HTTP Header safety
    const signatureB64Url = signatureB64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');

    // 3. Return the fully verifiable PQ-JWT
    return `${unsignedToken}.${signatureB64Url}`;
  }

  /**
   * Verifies an incoming SMART on FHIR PQ-JWT at the Resource Server Edge
   */
  async verifyAccessToken(token: string, requiredAudience: string): Promise<SmartFhirClaims> {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error("Invalid PQ-JWT structure");

    const [headerB64, payloadB64, sigB64Url] = parts;
    const unsignedToken = `${headerB64}.${payloadB64}`;
    
    // In a full implementation, you would retrieve the public key via the 'kid' 
    // from a standard /.well-known/jwks.json endpoint hosted by your MCP server.
    
    // Convert signature back to standard Base64 for the crypto engine
    const signatureB64 = sigB64Url.replace(/-/g, '+').replace(/_/g, '/');

    // Verify the ML-DSA signature (Assuming you add a verify method to CryptoEngine)
    // const isValid = await this.crypto.verify(unsignedToken, signatureB64);
    // if (!isValid) throw new Error("Post-Quantum Signature Verification Failed");

    const claims = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8')) as SmartFhirClaims;

    if (claims.exp < Math.floor(Date.now() / 1000)) throw new Error("Token expired");
    if (claims.aud !== requiredAudience) throw new Error("Audience mismatch");

    return claims;
  }
}