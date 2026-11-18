use wasm_bindgen::prelude::*;
use crystals_dilithium::ml_dsa_65::{Keypair, PublicKey, SecretKey};
use crystals_dilithium::RandomMode;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

#[wasm_bindgen]
pub struct PqcKeyPair {
    public_key_b64: String,
    private_key_b64: String,
}

#[wasm_bindgen]
impl PqcKeyPair {
    #[wasm_bindgen(getter)]
    pub fn public_key_b64(&self) -> String {
        self.public_key_b64.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn private_key_b64(&self) -> String {
        self.private_key_b64.clone()
    }
}

#[wasm_bindgen]
pub fn generate_pqc_keypair() -> PqcKeyPair {
    let keys = Keypair::generate(None).expect("Failed to generate FIPS-204 ML-DSA-65 keypair");
    PqcKeyPair {
        public_key_b64: BASE64.encode(keys.public.to_bytes()),
        private_key_b64: BASE64.encode(keys.secret.to_bytes()),
    }
}

#[wasm_bindgen]
pub fn sign_pqc_payload(message: &[u8], priv_key_bytes: &[u8]) -> Vec<u8> {
    let secret_key = SecretKey::from_bytes(priv_key_bytes)
        .expect("Invalid FIPS-204 ML-DSA-65 SecretKey bytes (expected 4032 bytes)");
    // Pure FIPS-204 ML-DSA-65 deterministic signing (produces 3309-byte signature)
    let signature = secret_key
        .sign(message, None, RandomMode::Deterministic)
        .expect("FIPS-204 signing failed");
    signature.to_vec()
}

#[wasm_bindgen]
pub fn verify_pqc_signature(
    sig_bytes: &[u8],
    message: &[u8],
    pub_key_bytes: &[u8],
) -> bool {
    let public_key = match PublicKey::from_bytes(pub_key_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    public_key.verify(message, sig_bytes, None)
}