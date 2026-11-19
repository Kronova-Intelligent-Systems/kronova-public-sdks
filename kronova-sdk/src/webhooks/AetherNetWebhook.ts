import * as crypto from 'crypto';
import { CryptoEngine, EncryptedEnvelope, PqcKeys } from '../security/crypto';

/**
 * Regulatory & industry compliance profiles supported by AetherNet QUAS
 */
export type QuasComplianceProfile =
  | 'AP2_UCC_ARTICLE_12'   // Institutional DeFi, Escrow & Programmable Credit
  | 'HIPAA_SMART_ON_FHIR'  // Healthcare EDI 837 / FHIR PHI Zero-Leakage
  | 'UNECE_WP29_R155_IOT'  // Autonomous Vehicles, Robotics & SCADA Telemetry
  | 'DOD_ZERO_TRUST';      // Defense & Sovereign Enclave Operations

/**
 * Metadata bound to the webhook envelope for deterministic audit trails
 */
export interface QuasWebhookMetadata {
  event_id: string;
  event_type: string;
  intent_ref?: string;
  compliance_profile: QuasComplianceProfile;
  pcr_attestation_quote?: string; // Hardware TEE quote (AWS Nitro / Intel TDX / Keystone)
  payload_sha256: string;         // Plaintext integrity hash for post-decapsulation audit
}

/**
 * The wire-format JSON body dispatched over HTTPS to the Gateway or Consumer
 */
export interface QuasWebhookEnvelope {
  protocol_version: '2.1';
  sender_did: string;
  recipient_did: string;
  metadata: QuasWebhookMetadata;
  encrypted_payload: EncryptedEnvelope;
}

/**
 * Strictly typed HTTP headers required by the AetherNet Cryptographic Airgap
 */
export interface QuasWebhookHeaders {
  [key: string]: string | undefined;
  'Content-Type': 'application/json';
  'x-aethernet-did': string;
  'x-aethernet-timestamp': string;
  'x-aethernet-signature': string;
  'x-aethernet-payload-b64': string;
  'x-aethernet-compliance': QuasComplianceProfile;
  'x-aethernet-attestation'?: string;
}

export interface DispatchWebhookOptions<T = unknown> {
  targetUrl: string;
  recipientDid: string;
  recipientKyberPubB64: string;
  eventType: string;
  payload: T;
  complianceProfile?: QuasComplianceProfile;
  intentRef?: string;
  pcrAttestationQuote?: string;
  serviceKey?: string;
}

export interface VerifyWebhookOptions {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  rawBody: string;
  senderPublicKeyB64: string;
  maxReplayWindowMs?: number; // Defaults to 5000ms (can be tightened to 500ms for HFT)
}

export interface WebhookVerificationResult {
  isValid: boolean;
  senderDid?: string;
  timestamp?: number;
  complianceProfile?: string;
  pcrAttestationQuote?: string;
  envelope?: QuasWebhookEnvelope;
  auditReceiptHash?: string;
  error?: string;
}

export class AetherNetWebhook {
  private cryptoEngine: CryptoEngine;
  private senderDid: string;
  private keys?: PqcKeys;

  constructor(senderDid: string, keys?: PqcKeys) {
    this.senderDid = senderDid;
    this.keys = keys;
    this.cryptoEngine = new CryptoEngine(keys);
  }

  /**
   * Seals an event payload in a FIPS-203 (ML-KEM-1024) + AES-256-GCM envelope
   * and signs the canonical HTTP transport string with FIPS-204 (ML-DSA-65).
   */
  async buildSignedWebhook<T = unknown>(
    options: DispatchWebhookOptions<T>
  ): Promise<{
    envelope: QuasWebhookEnvelope;
    rawBodyString: string;
    headers: QuasWebhookHeaders;
  }> {
    const {
      targetUrl,
      recipientDid,
      recipientKyberPubB64,
      eventType,
      payload,
      complianceProfile = 'AP2_UCC_ARTICLE_12',
      intentRef,
      pcrAttestationQuote,
    } = options;

    // 1. Compute SHA-256 of the canonical plaintext for zero-knowledge auditability
    const plaintextString = JSON.stringify(payload);
    const payloadSha256 = crypto
      .createHash('sha256')
      .update(plaintextString, 'utf-8')
      .digest('hex');

    // 2. Seal the plaintext inside a FIPS-203 ML-KEM + AES-256-GCM E2EE Envelope
    const encryptedEnvelope: EncryptedEnvelope = await this.cryptoEngine.encrypt(
      payload,
      recipientKyberPubB64
    );

    // 3. Construct the wire-format QUAS Webhook Envelope
    const envelope: QuasWebhookEnvelope = {
      protocol_version: '2.1',
      sender_did: this.senderDid,
      recipient_did: recipientDid,
      metadata: {
        event_id: `evt_${crypto.randomUUID()}`,
        event_type: eventType,
        intent_ref: intentRef,
        compliance_profile: complianceProfile,
        pcr_attestation_quote: pcrAttestationQuote,
        payload_sha256: payloadSha256,
      },
      encrypted_payload: encryptedEnvelope,
    };

    const rawBodyString = JSON.stringify(envelope);

    // 4. Construct the exact canonical string expected by ts-gateway & rust-ap2-core:
    //    METHOD:URI_PATH:TIMESTAMP:RAW_BODY
    const parsedUrl = new URL(targetUrl);
    const method = 'POST';
    const uriPath = parsedUrl.pathname;
    const timestamp = Date.now().toString();
    const messageToSign = `${method}:${uriPath}:${timestamp}:${rawBodyString}`;

    // 5. Base64-encode the canonical string to defeat HTTP proxy serialization drift
    const safePayloadB64 = Buffer.from(messageToSign, 'utf-8').toString('base64');

    // 6. Dynamically import the Rust WASM engine to generate a 3,309-byte FIPS-204 signature
    const wasm = await import('@kronova-intelligent-systems/aethernet-pqc-sdk');
    
    let privKeyBuffer: Buffer;
    if (this.keys?.dilithium?.priv) {
      privKeyBuffer = this.keys.dilithium.priv;
    } else {
      throw new Error(
        'AetherNetWebhook requires a valid FIPS-204 (ML-DSA) private key in PqcKeys to sign outbound webhooks.'
      );
    }

    const messageBuffer = Buffer.from(messageToSign, 'utf-8');
    const signatureBytes: Uint8Array = wasm.sign_pqc_payload(
      messageBuffer,
      privKeyBuffer
    );
    const signatureB64 = Buffer.from(signatureBytes).toString('base64');

    // 7. Assemble the Cryptographic KYA & Compliance Headers
    const headers: QuasWebhookHeaders = {
      'Content-Type': 'application/json',
      'x-aethernet-did': this.senderDid,
      'x-aethernet-timestamp': timestamp,
      'x-aethernet-signature': signatureB64,
      'x-aethernet-payload-b64': safePayloadB64,
      'x-aethernet-compliance': complianceProfile,
      ...(pcrAttestationQuote
        ? { 'x-aethernet-attestation': pcrAttestationQuote }
        : {}),
    };

    return { envelope, rawBodyString, headers };
  }

  /**
   * Seals, signs, and dispatches the webhook over HTTPS to the AetherNet Gateway or peer agent.
   */
  async dispatch<T = unknown>(
    options: DispatchWebhookOptions<T>
  ): Promise<{
    ok: boolean;
    status: number;
    eventId: string;
    response: unknown;
  }> {
    const { envelope, rawBodyString, headers } = await this.buildSignedWebhook(options);

    const requestHeaders: Record<string, string> = {
      ...headers,
      ...(options.serviceKey
        ? { Authorization: `Bearer ${options.serviceKey}` }
        : {}),
    };

    const res = await fetch(options.targetUrl, {
      method: 'POST',
      headers: requestHeaders,
      body: rawBodyString,
    });

    const contentType = res.headers.get('content-type') || '';
    const responseData = contentType.includes('application/json')
      ? await res.json()
      : await res.text();

    return {
      ok: res.ok,
      status: res.status,
      eventId: envelope.metadata.event_id,
      response: responseData,
    };
  }

  /**
   * Stateless Edge Verification for Gateways & Webhook Consumers.
   * Enforces the anti-replay time-lock window and verifies the FIPS-204 ML-DSA signature
   * without exposing the encrypted inner payload to the DMZ proxy.
   */
  static async verifyAtEdge(
    options: VerifyWebhookOptions
  ): Promise<WebhookVerificationResult> {
    const {
      method,
      path,
      headers,
      rawBody,
      senderPublicKeyB64,
      maxReplayWindowMs = 5000,
    } = options;

    const getHeader = (key: string): string | undefined => {
      const val = headers[key] ?? headers[key.toLowerCase()];
      return Array.isArray(val) ? val[0] : val;
    };

    const senderDid = getHeader('x-aethernet-did');
    const timestampStr = getHeader('x-aethernet-timestamp');
    const signatureB64 = getHeader('x-aethernet-signature');
    const safePayloadB64 = getHeader('x-aethernet-payload-b64');
    const complianceProfile = getHeader('x-aethernet-compliance');
    const pcrAttestationQuote = getHeader('x-aethernet-attestation');

    if (!senderDid || !timestampStr || !signatureB64) {
      return {
        isValid: false,
        error: 'Missing required AetherNet KYA headers (did, timestamp, or signature).',
      };
    }

    // 1. Time-Lock Anti-Replay Validation
    const timestamp = parseInt(timestampStr, 10);
    const now = Date.now();
    if (isNaN(timestamp) || Math.abs(now - timestamp) > maxReplayWindowMs) {
      return {
        isValid: false,
        senderDid,
        timestamp,
        error: `Webhook rejected: Timestamp outside ${maxReplayWindowMs}ms anti-replay window.`,
      };
    }

    // 2. Reconstruct the exact signed bytes via x-aethernet-payload-b64 (or fallback to rawBody)
    const canonicalMessageBuffer = safePayloadB64
      ? Buffer.from(safePayloadB64, 'base64')
      : Buffer.from(`${method.toUpperCase()}:${path}:${timestampStr}:${rawBody}`, 'utf-8');

    // 3. Verify the 3,309-byte FIPS-204 ML-DSA-65 signature in WebAssembly
    const wasm = await import('@kronova-intelligent-systems/aethernet-pqc-sdk');
    const sigBuffer = Buffer.from(signatureB64, 'base64');
    const pubKeyBuffer = Buffer.from(senderPublicKeyB64, 'base64');

    const isSignatureValid = wasm.verify_pqc_signature(
      sigBuffer,
      canonicalMessageBuffer,
      pubKeyBuffer
    );

    if (!isSignatureValid) {
      return {
        isValid: false,
        senderDid,
        timestamp,
        error: 'Cryptographic Airgap Violation: Invalid FIPS-204 ML-DSA signature.',
      };
    }

    // 4. Parse outer envelope & compute immutable Audit Receipt Hash for Canton Daml logging
    let parsedEnvelope: QuasWebhookEnvelope | undefined;
    try {
      parsedEnvelope = JSON.parse(rawBody) as QuasWebhookEnvelope;
    } catch {
      return {
        isValid: false,
        senderDid,
        timestamp,
        error: 'Malformed QuasWebhookEnvelope JSON body.',
      };
    }

    // Deterministic audit hash binding DID + Event ID + Timestamp + Signature + PCR Quote
    const auditReceiptHash = crypto
      .createHash('sha256')
      .update(
        `${senderDid}:${parsedEnvelope.metadata.event_id}:${timestampStr}:${signatureB64}:${pcrAttestationQuote || 'EDGE'}`
      )
      .digest('hex');

    return {
      isValid: true,
      senderDid,
      timestamp,
      complianceProfile,
      pcrAttestationQuote,
      envelope: parsedEnvelope,
      auditReceiptHash,
    };
  }

  /**
   * Decapsulates the inner FIPS-203 ML-KEM + AES-256-GCM payload inside the authorized Enclave/Agent
   * and verifies the inner SHA-256 integrity hash.
   */
  decryptVerifiedEnvelope<T = unknown>(envelope: QuasWebhookEnvelope): T {
    const decryptedPayload = this.cryptoEngine.decrypt(envelope.encrypted_payload);
    const decryptedStr = JSON.stringify(decryptedPayload);
    const computedHash = crypto
      .createHash('sha256')
      .update(decryptedStr, 'utf-8')
      .digest('hex');

    if (computedHash !== envelope.metadata.payload_sha256) {
      throw new Error(
        'Inner payload SHA-256 mismatch: Decapsulated data does not match signed metadata.'
      );
    }

    return decryptedPayload as T;
  }
}