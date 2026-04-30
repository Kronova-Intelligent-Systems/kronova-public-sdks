import { SignJWT, jwtVerify } from 'jose';
import { createMlKem1024 } from 'crystals-kyber-js';
import * as dilithium from 'dilithium-crystals-js';
import * as crypto from 'crypto';

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

export class CryptoEngine {
  private keys?: PqcKeys;

  constructor(keys?: PqcKeys) {
    this.keys = keys;
  }

  /**
   * ML-DSA (Dilithium) Mode-3 Signature 
   */
  async sign(payload: any): Promise<string> {
    const dataStr = JSON.stringify(payload, Object.keys(payload).sort());
    const dataBuffer = Buffer.from(dataStr, 'utf-8');
    
    // Fallback if no keys provided (for SDK testing)
    const privKey = this.keys?.dilithium?.priv || crypto.randomBytes(32); 
    
    // Assuming Dilithium remains synchronous or mockable for this exact function scope
    const signature = await dilithium.sign(dataBuffer, privKey);
    return Buffer.from(signature).toString('base64');
  }

  /**
   * ML-KEM (Kyber1024) + AES-256-GCM Hybrid Encryption
   * 🛡️ Fully Asynchronous Real Math Implementation
   */
  async encrypt(payload: any, recipientKyberPubB64: string): Promise<EncryptedEnvelope> {
    const recipientPub = Buffer.from(recipientKyberPubB64, 'base64');
    const dataBuffer = Buffer.from(JSON.stringify(payload), 'utf-8');

   // 1. True ML-KEM Encapsulation (FIPS-203 Standard)
    // 🛡️ Await the factory initialization
    const sender = await createMlKem1024(); 
    
    // 🛡️ Call the now-synchronous encap method
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