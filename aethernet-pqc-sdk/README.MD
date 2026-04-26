# AetherNet PQC SDK 🛡️

[![NPM Version](https://img.shields.io/npm/v/@kronova-intelligent-systems/aethernet-pqc-sdk.svg)](https://www.npmjs.com/package/@kronova-intelligent-systems/aethernet-pqc-sdk)
[![Crates.io](https://img.shields.io/crates/v/aethernet-pqc-sdk.svg)](https://crates.io/crates/aethernet-pqc-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

The official Post-Quantum Cryptography (PQC) execution engine for the **AetherNet Protocol**. 

This SDK provides a unified, FIPS-204 compliant implementation of the ML-DSA (Dilithium3) digital signature algorithm. It is engineered for autonomous AI agents, Trusted Execution Environments (TEEs), and highly secure enterprise gateways operating on the AetherNet network.

Built natively in pure Rust for bare-metal performance, and compiled to highly optimized WebAssembly (WASM) for universal compatibility across Node.js, Edge runtimes, and the browser.

## Architecture

AetherNet PQC SDK solves the "Cross-Crate Cryptographic Drift" problem by providing a single mathematical source of truth across the entire tech stack:
* **Backend (Rust):** Natively importable via `crates.io` for high-frequency trading matching engines, HSMs, and hardware enclaves.
* **Frontend/Edge (NPM):** Importable as a WASM module for Next.js Server Actions, Express Gateways, and React clients.

## Installation

### For Node.js / TypeScript (via NPM)
```bash
npm install @kronova-intelligent-systems/aethernet-pqc-sdk
```

### For Rust/Backend (via Cargo)
```Ini, TOML

[dependencies]
aethernet-pqc-sdk = "0.1.0"
```

Quick Start (TypeScript / Node.js)

1. Generate a Post-Quantum Keypair

```TypeScript

import { generate_pqc_keypair } from '@kronova-intelligent-systems/aethernet-pqc-sdk';

// Generates a FIPS-204 ML-DSA keypair
const keys = generate_pqc_keypair();
console.log("Public Key (Base64):", keys.public_key_b64);
console.log("Private Key (Base64):", keys.private_key_b64);
```
2. Sign an Enterprise AP2 Payload
```TypeScript
import { sign_pqc_payload } from '@kronova-intelligent-systems/aethernet-pqc-sdk';

const payload = Buffer.from(JSON.stringify({ 
  intent_ref: "WORKFLOW-123", 
  amount: 5000 
}), 'utf-8');

const privateKeyBuffer = Buffer.from(keys.private_key_b64, 'base64');

// Generates a detached 3309-byte ML-DSA signature
const signature = sign_pqc_payload(payload, privateKeyBuffer);
console.log("Signature Generated.");
```
3. Verify a Signature at the Edge
```TypeScript
import { verify_pqc_signature } from '@kronova-intelligent-systems/aethernet-pqc-sdk';

const isValid = verify_pqc_signature(
  signatureBuffer, 
  payloadBuffer, 
  publicKeyBuffer
);

if (isValid) {
  console.log("✅ Post-Quantum Edge Verification Successful");
} else {
  console.error("❌ Cryptographic Airgap Violation");
}
```
### Protocol Specifications
- Standard: NIST FIPS-204 (ML-DSA)

- Parameter Set: Dilithium3 (ML-DSA-65)

- Public Key Length: 1952 bytes

- Signature Length: 3309 bytes

- Security Category: Post-Quantum Secure (NIST Level 3)

### About Kronova Intelligent Systems
AetherNet is the infrastructure layer for the autonomous economy, enabling mathematically pure, post-quantum secure intent matching and ledger settlement for AI agents and RWA tokenization.

Discover ![AetherNet](https://kronova.io) | ![Documentation](https://www.google.com/search?q=https://docs.kronova.io)
