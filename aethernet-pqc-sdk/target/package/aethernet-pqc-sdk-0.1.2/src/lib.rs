use wasm_bindgen::prelude::*;
use crystals_dilithium::dilithium3::{PublicKey, SecretKey, Keypair};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

// 🛡️ 1. The Keypair Struct exported to Javascript
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

// 🛡️ 2. The Generation Method (Matches README)
#[wasm_bindgen]
pub fn generate_pqc_keypair() -> PqcKeyPair {
    // Generates the FIPS-204 keypair securely using the injected JS entropy
let keys = Keypair::generate(None).expect("Failed to generate FIPS-204 keypair from OS entropy");    
    PqcKeyPair {
        public_key_b64: BASE64.encode(keys.public.to_bytes()),
        private_key_b64: BASE64.encode(keys.secret.to_bytes()),
    }
}

// 🛡️ 3. The Signing Method (Renamed to match README)
#[wasm_bindgen]
pub fn sign_pqc_payload(
    payload: &[u8], 
    secret_key_bytes: &[u8]
) -> Result<Vec<u8>, JsValue> {
    let secret_key = SecretKey::from_bytes(secret_key_bytes)
        .map_err(|_| JsValue::from_str("Invalid FIPS-204 Secret Key bytes"))?;

    let signature = secret_key.sign(payload);
    Ok(signature.to_vec())
}

#[wasm_bindgen]
pub fn verify_pqc_signature(
    sig_bytes: &[u8], 
    message: &[u8], 
    pub_key_bytes: &[u8]
) -> bool {
    // 1. Safely parse the Public Key from the raw bytes
    let public_key = match PublicKey::from_bytes(pub_key_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // 2. Natively execute the Pure Rust detached verification! 
    // No padding, no memory hacking, no Attached Signature arrays required.
    public_key.verify(message, sig_bytes)
}
