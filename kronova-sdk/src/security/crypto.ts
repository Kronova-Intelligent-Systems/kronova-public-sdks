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
   * ML-DSA (Dilithium3 / FIPS-204) Signature Generation
   * Executed via natively compiled Rust WebAssembly.
   */
  async sign(payload: any): Promise<string> {
    const wasm = await this.getWasm();

    // Deterministic JSON stringification for payload consistency
    const dataStr = JSON.stringify(payload, Object.keys(payload).sort());
    const dataBuffer = Buffer.from(dataStr, 'utf-8');
    
    let privKey = this.keys?.dilithium?.priv;

    // 🛡️ Fallback: Generate a mathematically valid ephemeral FIPS-204 key 
    // if one isn't provided, preventing Rust panic on strict byte-length checks.
    if (!privKey) {
      console.warn("⚠️ [CryptoEngine] No ML-DSA private key provided. Generating ephemeral FIPS-204 keypair...");
      const kp = wasm.generate_pqc_keypair();
      privKey = Buffer.from(kp.private_key_b64, 'base64');
      
      // Cache the ephemeral keys for subsequent operations in this session
      if (!this.keys) this.keys = { dilithium: {} as any, kyber: {} as any };
      this.keys.dilithium = {
        pub: Buffer.from(kp.public_key_b64, 'base64'),
        priv: privKey
      };
    }

    // Cross the WASM boundary to execute pure Rust math
    const signatureBytes = wasm.sign_pqc_payload(dataBuffer, privKey);
    return Buffer.from(signatureBytes).toString('base64');
  }

  /**
   * ML-DSA (Dilithium3 / FIPS-204) Signature Verification
   * Required for SMART on FHIR PQ-JWT authentication.
   */
  async verify(payload: any, signatureB64: string, providedPubKey?: Buffer): Promise<boolean> {
    const wasm = await this.getWasm();

    const dataStr = JSON.stringify(payload, Object.keys(payload).sort());
    const dataBuffer = Buffer.from(dataStr, 'utf-8');
    const sigBytes = Buffer.from(signatureB64, 'base64');
    
    const pubKey = providedPubKey || this.keys?.dilithium?.pub;
    if (!pubKey) {
      throw new Error("❌ [CryptoEngine] Verification failed: No ML-DSA public key available.");
    }

    return wasm.verify_pqc_signature(sigBytes, dataBuffer, pubKey);
  }

  /**
   * ML-KEM (Kyber1024 / FIPS-203) + AES-256-GCM Hybrid Encryption
   * 🛡️ Fully Asynchronous Real Math Implementation
   */
  async encrypt(payload: any, recipientKyberPubB64: string): Promise<EncryptedEnvelope> {
    const recipientPub = Buffer.from(recipientKyberPubB64, 'base64');
    const dataBuffer = Buffer.from(JSON.stringify(payload), 'utf-8');

    // 1. True ML-KEM Encapsulation (FIPS-203 Standard)
    const sender = await createMlKem1024(); 
    
    // 🛡️ Execute encapsulation to generate the KEM Ciphertext and Shared Secret
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
      authTag: authTag.toString('base64')
    };
  }
}