import { createMlKem1024 } from 'crystals-kyber-js';
import * as crypto from 'crypto';

// ==========================================
// ENTERPRISE DATA MODELS & INTERFACES
// ==========================================

export interface PqcKeys {
  dilithium: { pub: Buffer; priv: Buffer };
  kyber: { pub: Buffer; priv: Buffer };
}

export interface EncryptedEnvelope {
  kemCiphertext: string;
  aesCiphertext: string;
  iv: string;
  authTag: string;
}

// ==========================================
// AETHERNET PQC CRYPTO ENGINE
// ==========================================

export class CryptoEngine {
  private keys?: PqcKeys;
  private wasmModule: any = null;

  constructor(keys?: PqcKeys) {
    this.keys = keys;
  }

  /**
   * 🛡️ Dynamically load the Kronova Native WASM Module
   * Bypasses the initial bundle size penalty and ensures 1:1 Rust TEE parity.
   */
  private async getWasm() {
    if (!this.wasmModule) {
      // Dynamically pull the exact math executed in the bare-metal Rust TEE
      this.wasmModule = await import('@kronova-intelligent-systems/aethernet-pqc-sdk');
    }
    return this.wasmModule;
  }

  /**
   * Returns Base64-encoded public keys for KYA registration & discovery
   */
  getPublicKeys(): { dilithium: string; kyber: string } {
    return {
      dilithium: this.keys?.dilithium?.pub
        ? this.keys.dilithium.pub.toString('base64')
        : '',
      kyber: this.keys?.kyber?.pub
        ? this.keys.kyber.pub.toString('base64')
        : '',
    };
  }

  /**
   * ML-DSA-65 (NIST FIPS-204) Signature Generation (3,309-byte signature)
   * Executed via natively compiled Rust WebAssembly.
   */
  async sign(payload: any): Promise<string> {
    const wasm = await this.getWasm();

    // Preserve raw canonical strings (e.g. METHOD:URI:TIMESTAMP:BODY) or deterministically stringify objects
    const dataStr =
      typeof payload === 'string'
        ? payload
        : JSON.stringify(payload, Object.keys(payload).sort());
    const dataBuffer = Buffer.from(dataStr, 'utf-8');

    let privKey = this.keys?.dilithium?.priv;

    // 🛡️ Fallback: Generate a valid 4,032-byte ephemeral FIPS-204 ML-DSA-65 key
    // if one isn't provided or if a legacy 4,000-byte Round 3 buffer was passed.
    if (!privKey || privKey.length !== 4032) {
      console.warn(
        '⚠️ [CryptoEngine] No valid 4,032-byte ML-DSA-65 private key provided. Generating ephemeral FIPS-204 keypair...'
      );
      const kp = wasm.generate_pqc_keypair();
      privKey = Buffer.from(kp.private_key_b64, 'base64');

      // Cache the ephemeral keys for subsequent operations in this session
      if (!this.keys) this.keys = { dilithium: {} as any, kyber: {} as any };
      this.keys.dilithium = {
        pub: Buffer.from(kp.public_key_b64, 'base64'),
        priv: privKey,
      };
    }

    // Cross the WASM boundary to execute pure Rust FIPS-204 math
    const signatureBytes = wasm.sign_pqc_payload(dataBuffer, privKey);
    return Buffer.from(signatureBytes).toString('base64');
  }

  /**
   * ML-DSA-65 (NIST FIPS-204) Signature Verification
   * Required for SMART on FHIR PQ-JWT authentication and Edge Webhook verification.
   */
  async verify(
    payload: any,
    signatureB64: string,
    providedPubKey?: Buffer | string
  ): Promise<boolean> {
    const wasm = await this.getWasm();

    const dataStr =
      typeof payload === 'string'
        ? payload
        : JSON.stringify(payload, Object.keys(payload).sort());
    const dataBuffer = Buffer.from(dataStr, 'utf-8');
    const sigBytes = Buffer.from(signatureB64, 'base64');

    const pubKey =
      typeof providedPubKey === 'string'
        ? Buffer.from(providedPubKey, 'base64')
        : providedPubKey || this.keys?.dilithium?.pub;

    if (!pubKey || pubKey.length !== 1952) {
      throw new Error(
        '❌ [CryptoEngine] Verification failed: No valid 1,952-byte ML-DSA-65 public key available.'
      );
    }

    return wasm.verify_pqc_signature(sigBytes, dataBuffer, pubKey);
  }

  /**
   * ML-KEM-1024 (NIST FIPS-203) + AES-256-GCM Hybrid Encryption
   * 🛡️ Fully Asynchronous Real Math Implementation
   */
  async encrypt(
    payload: any,
    recipientKyberPubB64: string
  ): Promise<EncryptedEnvelope> {
    const recipientPub = Buffer.from(recipientKyberPubB64, 'base64');
    const dataBuffer = Buffer.from(JSON.stringify(payload), 'utf-8');

    // 1. True ML-KEM-1024 Encapsulation (FIPS-203 Standard)
    const sender = await createMlKem1024();

    // 🛡️ Execute encapsulation to generate the 1,568-byte KEM Ciphertext and 32-byte Shared Secret
    const [ct, sharedSecret] = sender.encap(recipientPub);

    // 2. AES-256-GCM Encryption using the Shared Secret
    const sharedSecretBuffer = Buffer.from(sharedSecret);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', sharedSecretBuffer, iv);

    let aesCiphertext = cipher.update(dataBuffer);
    aesCiphertext = Buffer.concat([aesCiphertext, cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      kemCiphertext: Buffer.from(ct).toString('base64'),
      aesCiphertext: aesCiphertext.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
    };
  }

  /**
   * ML-KEM-1024 (NIST FIPS-203) + AES-256-GCM Hybrid Decryption
   * Unlocks incoming AetherNet E2EE & QUAS Webhook Envelopes
   */
  async decrypt(envelope: EncryptedEnvelope): Promise<any> {
    const privKey = this.keys?.kyber?.priv;
    if (!privKey || privKey.length !== 3168) {
      throw new Error(
        '❌ [CryptoEngine] Decryption failed: No valid 3,168-byte ML-KEM-1024 private key available.'
      );
    }

    const kemCiphertext = Buffer.from(envelope.kemCiphertext, 'base64');
    const recipient = await createMlKem1024();
    const sharedSecret = recipient.decap(kemCiphertext, privKey);

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      Buffer.from(sharedSecret),
      Buffer.from(envelope.iv, 'base64')
    );
    decipher.setAuthTag(Buffer.from(envelope.authTag, 'base64'));

    let decrypted = decipher.update(Buffer.from(envelope.aesCiphertext, 'base64'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return JSON.parse(decrypted.toString('utf-8'));
  }
}