use wasm_bindgen::prelude::*;
use crystals_dilithium::dilithium3::PublicKey;

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
