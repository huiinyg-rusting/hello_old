use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hmac::Hmac;
use sha3::{Digest, Sha3_256};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const ARGON2_MEMORY_KIB: u32 = 65536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const ARGON2_OUTPUT_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

pub fn argon2id_hash(password: &[u8], salt: &[u8]) -> [u8; ARGON2_OUTPUT_LEN] {
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM, Some(ARGON2_OUTPUT_LEN))
        .expect("argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; ARGON2_OUTPUT_LEN];
    argon2.hash_password_into(password, salt, &mut out).expect("argon2 hash");
    out
}

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let mut hkdf = HmacSha256::new_from_slice(ikm).expect("HMAC key");
    hkdf.update(salt);
    hkdf.update(info);
    let mut okm = vec![0u8; out_len];
    hkdf.finalize_into(&mut okm);
    okm
}

pub fn derive_wrapping_keys(master_key: &[u8; 32]) -> ([u8; 32]; 6) {
    let labels = [
        b"wrap-rsa",
        b"wrap-kyber",
        b"wrap-mceliece",
        b"wrap-frodokem",
        b"wrap-dilithium",
        b"wrap-serpent-dek",
    ];
    let mut keys = [ [0u8; 32]; 6 ];
    for (i, label) in labels.iter().enumerate() {
        let key = hkdf_sha256(master_key, b"hello-old-v1", label, 32);
        keys[i].copy_from_slice(&key);
    }
    keys
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data).into()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

pub fn decrypt(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 12 + 16 {
        return None;
    }
    let (nonce, ct) = blob.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(Nonce::from_slice(nonce), ct).ok()
}

pub fn zeroize(buf: &mut [u8]) {
    buf.zeroize();
}