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
    // Manual HKDF-SHA256: Extract + Expand
    use hmac::Mac;
    let mut prk = <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC key");
    prk.update(ikm);
    let prk = prk.finalize().into_bytes();
    let mut okm = vec![0u8; out_len];
    let mut t = Vec::new();
    let mut counter: u8 = 1;
    let mut pos = 0;
    while pos < out_len {
        let mut hmac = <HmacSha256 as Mac>::new_from_slice(&prk).expect("HMAC key");
        hmac.update(&t);
        hmac.update(info);
        hmac.update(&[counter]);
        t = hmac.finalize().into_bytes().to_vec();
        let n = (out_len - pos).min(32);
        okm[pos..pos + n].copy_from_slice(&t[..n]);
        pos += n;
        counter = counter.wrapping_add(1);
    }
    okm
}

pub fn derive_wrapping_keys(master_key: &[u8; 32]) -> [[u8; 32]; 6] {
    let labels: [&[u8]; 6] = [
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

/// Cache-wipe: flush every cache line overlapping [ptr, ptr+len).
/// x86-64 CLFLUSH is supported on all x86-64 CPUs; no CPU feature gate needed.
pub fn flush_mem(ptr: *const u8, len: usize) {
    if len == 0 || ptr.is_null() {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    {
        const LINE: usize = 64;
        let start = ptr as usize;
        let end = start.saturating_add(len);
        let mut a = start;
        while a < end {
            unsafe {
                std::arch::x86_64::_mm_clflush(a as *const u8);
            }
            a = a.saturating_add(LINE);
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (ptr, len);
    }
}

/// Timing equalizer: execute a fixed amount of volatile, dependency-chained
/// arithmetic so that success and failure paths take indistinguishable time.
pub fn burn_cycles(rounds: u64) {
    let mut acc: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut i: u64 = rounds;
    while i != 0 {
        acc = acc.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        acc = acc.rotate_left(17) ^ acc;
        std::hint::black_box(acc);
        i = i.wrapping_sub(1);
    }
    std::hint::black_box(acc);
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