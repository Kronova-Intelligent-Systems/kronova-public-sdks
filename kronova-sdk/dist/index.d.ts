import { z } from 'zod';

declare class AetherNetClient {
    private gatewayUrl;
    private privateKeyBytes;
    /**
     * Initializes the client with the agent's Dilithium3 private key
     */
    constructor(gatewayUrl: string, privateKeyB64: string);
    /**
     * Enterprise PQC Signing & Dispatch
     * Automatically constructs the mathematically pure payload and injects headers.
     */
    sendSettlement(uriPath: string, payload: any): Promise<any>;
}

declare const AP2IntentSchema: z.ZodObject<{
    type: z.ZodLiteral<"AP2_INTENT">;
    mandate_id: z.ZodString;
    issuer: z.ZodString;
    delegate: z.ZodString;
    constraints: z.ZodObject<{
        max_amount: z.ZodNumber;
        currency: z.ZodLiteral<"USDCx">;
        expires_at: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        max_amount: number;
        currency: "USDCx";
        expires_at: string;
    }, {
        max_amount: number;
        currency: "USDCx";
        expires_at: string;
    }>;
}, "strip", z.ZodTypeAny, {
    type: "AP2_INTENT";
    mandate_id: string;
    issuer: string;
    delegate: string;
    constraints: {
        max_amount: number;
        currency: "USDCx";
        expires_at: string;
    };
}, {
    type: "AP2_INTENT";
    mandate_id: string;
    issuer: string;
    delegate: string;
    constraints: {
        max_amount: number;
        currency: "USDCx";
        expires_at: string;
    };
}>;
declare const AP2CartSchema: z.ZodObject<{
    type: z.ZodLiteral<"AP2_CART">;
    cart_id: z.ZodString;
    intent_ref: z.ZodString;
    items: z.ZodArray<z.ZodObject<{
        desc: z.ZodString;
        qty: z.ZodNumber;
        unit_price: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        desc: string;
        qty: number;
        unit_price: number;
    }, {
        desc: string;
        qty: number;
        unit_price: number;
    }>, "many">;
    total_amount: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    type: "AP2_CART";
    cart_id: string;
    intent_ref: string;
    items: {
        desc: string;
        qty: number;
        unit_price: number;
    }[];
    total_amount: number;
}, {
    type: "AP2_CART";
    cart_id: string;
    intent_ref: string;
    items: {
        desc: string;
        qty: number;
        unit_price: number;
    }[];
    total_amount: number;
}>;
declare const AP2PaymentSchema: z.ZodObject<{
    type: z.ZodLiteral<"AP2_PAYMENT">;
    intent_ref: z.ZodString;
    cart_ref: z.ZodString;
    final_amount: z.ZodNumber;
    agent_signature: z.ZodString;
}, "strip", z.ZodTypeAny, {
    type: "AP2_PAYMENT";
    intent_ref: string;
    cart_ref: string;
    final_amount: number;
    agent_signature: string;
}, {
    type: "AP2_PAYMENT";
    intent_ref: string;
    cart_ref: string;
    final_amount: number;
    agent_signature: string;
}>;

interface PqcKeys {
    dilithium: {
        pub: Buffer;
        priv: Buffer;
    };
    kyber: {
        pub: Buffer;
        priv: Buffer;
    };
}
interface EncryptedEnvelope {
    kemCiphertext: string;
    aesCiphertext: string;
    iv: string;
    authTag: string;
}
declare class CryptoEngine {
    private keys?;
    constructor(keys?: PqcKeys);
    /**
     * ML-DSA (Dilithium) Mode-3 Signature
     */
    sign(payload: any): Promise<string>;
    /**
     * ML-KEM (Kyber1024) + AES-256-GCM Hybrid Encryption
     * 🛡️ Fully Asynchronous Real Math Implementation
     */
    encrypt(payload: any, recipientKyberPubB64: string): Promise<EncryptedEnvelope>;
}

interface TransportMessage {
    recipient_did: string;
    metadata: Record<string, string>;
    payload: EncryptedEnvelope;
}
declare class AetherTransport {
    private client;
    private agentDid;
    private baseUrl;
    private crypto;
    constructor(supabaseUrl: string, serviceKey: string, agentDid: string, baseUrl: string, crypto: CryptoEngine);
    /**
     * Sends a zero-trust AetherNet v2.1 Message Envelope
     */
    sendMessage(message: TransportMessage): Promise<any>;
    /**
     * Listens for incoming AetherNet messages via Supabase Realtime
     */
    subscribeToInbox(callback: (msg: any) => void): void;
}

type AP2Cart = z.infer<typeof AP2CartSchema>;
declare class AP2Wallet {
    private transport;
    private crypto;
    constructor(transport: AetherTransport, crypto: CryptoEngine);
    pay(cart: AP2Cart): Promise<any>;
}

interface SmartFhirClaims {
    iss: string;
    sub: string;
    aud: string;
    exp: number;
    iat: number;
    jti: string;
    scope: string;
    patient?: string;
    kronova_did?: string;
}
declare class KronovaSmartAuth {
    private crypto;
    private issuerUrl;
    constructor(crypto: CryptoEngine, issuerUrl: string);
    /**
     * Generates a Post-Quantum JSON Web Token (PQ-JWT) for FHIR Authorization
     */
    issueAccessToken(claims: Omit<SmartFhirClaims, 'iss' | 'iat' | 'jti'>): Promise<string>;
    /**
     * Verifies an incoming SMART on FHIR PQ-JWT at the Resource Server Edge
     */
    verifyAccessToken(token: string, requiredAudience: string): Promise<SmartFhirClaims>;
}

export { AP2CartSchema, AP2IntentSchema, AP2PaymentSchema, AP2Wallet, AetherNetClient, AetherTransport, CryptoEngine, KronovaSmartAuth, type SmartFhirClaims };
