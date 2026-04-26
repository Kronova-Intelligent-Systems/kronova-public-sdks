import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { Database } from '../types/supabase-types';
import { CryptoEngine, EncryptedEnvelope } from '../security/crypto';

// 1. The Enterprise Interface definition
export interface TransportMessage {
  recipient_did: string;
  metadata: Record<string, string>;
  payload: EncryptedEnvelope; // Enforces the hybrid KEM/AES envelope from your CryptoEngine
}

export class AetherTransport {
  private client: SupabaseClient<Database>;
  private agentDid: string;
  private baseUrl: string;
  private crypto: CryptoEngine; // 🛡️ Added missing property

  // 2. Inject all required dependencies into the constructor
  constructor(
    supabaseUrl: string, 
    serviceKey: string, 
    agentDid: string,
    baseUrl: string,
    crypto: CryptoEngine
  ) {
    this.client = createClient<Database>(supabaseUrl, serviceKey);
    this.agentDid = agentDid;
    this.baseUrl = baseUrl;
    this.crypto = crypto;
  }

  /**
   * Sends a zero-trust AetherNet v2.1 Message Envelope
   */
  async sendMessage(message: TransportMessage) {
    const method = 'POST';
    const path = '/v1/messages';
    const timestamp = Date.now().toString();
    
    // 3. Construct the body using the data from the single interface object
    const body = {
      protocol_version: '2.1',
      recipient_did: message.recipient_did,
      metadata: message.metadata,
      encrypted_payload: message.payload
    };

    // Construct the exact same deterministic string the Gateway expects
    const signaturePayload = `${method}:${path}:${timestamp}:${JSON.stringify(body, Object.keys(body).sort())}`;
    
    // Sign the HTTP intent with the Agent's ML-DSA (Dilithium) Private Key
    const signature = this.crypto.sign(signaturePayload);

    // Dispatch with Post-Quantum Signed Headers
    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'x-aethernet-did': this.agentDid,
        'x-aethernet-timestamp': timestamp,
        'x-aethernet-signature': signature
      },
      body: JSON.stringify(body)
    });

    return response.json();
  }

  /**
   * Listens for incoming AetherNet messages via Supabase Realtime
   */
  subscribeToInbox(callback: (msg: any) => void) {
    this.client
      .channel('aethernet-inbox')
      .on('postgres_changes', { 
        event: 'INSERT', 
        schema: 'public', 
        table: 'aethernet_messages',
        filter: `sender_id=eq.${this.agentDid}`
      }, (payload) => callback(payload.new))
      .subscribe();
  }
}