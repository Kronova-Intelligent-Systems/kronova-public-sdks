// kronova-sdk/src/client.ts
import dilithiumPromise from 'dilithium-crystals-js';

export class AetherNetClient {
    private gatewayUrl: string;
    private privateKeyBytes: Uint8Array;

    /**
     * Initializes the client with the agent's Dilithium3 private key
     */
    constructor(gatewayUrl: string, privateKeyB64: string) {
        this.gatewayUrl = gatewayUrl;
        this.privateKeyBytes = new Uint8Array(Buffer.from(privateKeyB64, 'base64'));
    }

    /**
     * Enterprise PQC Signing & Dispatch
     * Automatically constructs the mathematically pure payload and injects headers.
     */
    async sendSettlement(uriPath: string, payload: any): Promise<any> {
        // 1. Initialize PQC Engine
        const dilithium = await dilithiumPromise;

        // 2. Prepare the raw payload
        const rawBodyString = JSON.stringify(payload);
        const timestamp = Date.now().toString();
        const method = "POST";

        // 3. Construct the exact bytes expected by the Rust TEE
        const messageToSign = `${method}:${uriPath}:${timestamp}:${rawBodyString}`;
        const messageBytes = new TextEncoder().encode(messageToSign);

        // 4. Execute ML-DSA (Dilithium3) Signature
        const signatureBytes = dilithium.sign(this.privateKeyBytes, messageBytes, 3);
        const signatureB64 = Buffer.from(signatureBytes).toString('base64');

        // 5. Dispatch with Enterprise Headers
        const response = await fetch(`${this.gatewayUrl}${uriPath}`, {
            method: method,
            headers: {
                "Content-Type": "application/json",
                "x-aethernet-timestamp": timestamp,
                "x-aethernet-signature": signatureB64
            },
            body: rawBodyString
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`AetherNet Node Rejected: ${response.status} - ${errorText}`);
        }

        return await response.json();
    }
}