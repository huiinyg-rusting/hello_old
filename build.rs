use std::fs;
use std::io::Write;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use getrandom::getrandom;
use sha3::{Digest, Sha3_256};

include!("shared.rs");

const DEFAULT_PASSWORD: &[u8] = PASSWORD;
const H1: usize = KEY_LEN / 2;
const ARGON2_MEMORY_KIB: u32 = 1024;
const ARGON2_ITERATIONS: u32 = 1;
const ARGON2_PARALLELISM: u32 = 1;
const ARGON2_SALT_LEN: usize = 32;
const ARGON2_OUTPUT_LEN: usize = 32;

fn sha3_256(data: &[u8]) -> [u8; 32] {
    Sha3_256::digest(data).into()
}

fn nonce_for(key: &[u8; 32], label: &[u8]) -> [u8; 12] {
    let h = Sha3_256::new().chain_update(key).chain_update(label).finalize();
    let mut n = [0u8; 12];
    n.copy_from_slice(&h[..12]);
    n
}

fn encrypt(key: &[u8; 32], label: &[u8], plain: &[u8]) -> Vec<u8> {
    let nonce = nonce_for(key, label);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain)
        .expect("encrypt failed");
    let mut blob = Vec::with_capacity(12 + ct.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    blob
}

fn write_blob(out_dir: &str, name: &str, blob: &[u8]) {
    let path = format!("{out_dir}/{name}");
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(blob).unwrap();
}

fn build_seed() -> u64 {
    let mut seed = [0u8; 32];
    getrandom(&mut seed).expect("getrandom failed");
    u64::from_le_bytes(seed[..8].try_into().unwrap())
}

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E3779B97F4A7C15))
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn fill(&mut self, out: &mut [u8]) {
        let mut i = 0;
        while i < out.len() {
            let x = self.next_u64();
            let n = (out.len() - i).min(8);
            out[i..i + n].copy_from_slice(&x.to_le_bytes()[..n]);
            i += n;
        }
    }
    fn u8(&mut self) -> u8 {
        self.next_u64() as u8
    }
    fn u16(&mut self) -> u16 {
        self.next_u64() as u16
    }
    fn choice(&mut self, n: usize) -> usize {
        (self.next_u64() as usize) % n
    }
}

fn argon2id_hash(password: &[u8], salt: &[u8]) -> [u8; ARGON2_OUTPUT_LEN] {
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM, Some(ARGON2_OUTPUT_LEN))
        .expect("argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; ARGON2_OUTPUT_LEN];
    argon2.hash_password_into(password, salt, &mut out).expect("argon2 hash");
    out
}

fn gen_opaque_predicate(rng: &mut Rng) -> u8 {
    match rng.choice(4) {
        0 => 0xE0,
        1 => 0xE1,
        2 => 0xE2,
        _ => 0xE3,
    }
}

fn gen_vm_program(k1: &[u8; 32], k2: &[u8; 32], km: &[u8; 64], seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut prog = Vec::new();
    
    let mut instr_id = 0u16;
    
    let opaque_labels: Vec<u8> = (0..64).map(|_| gen_opaque_predicate(&mut rng)).collect();
    
    for (half_idx, key_half) in [k1.as_slice(), k2.as_slice()].iter().enumerate() {
        let base = half_idx * H1;
        
        for i in 0..H1 {
            let mask = key_half[i] ^ km[base + i];
            let target_addr = (base + i) as u8;
            
            let obfuscation_depth = rng.choice(3) + 1;
            
            for _ in 0..obfuscation_depth {
                let op = match rng.choice(6) {
                    0 => 0xA0,
                    1 => 0xA1,
                    2 => 0xA2,
                    3 => 0xA3,
                    4 => 0xA4,
                    _ => 0xA5,
                };
                let reg = rng.choice(16) as u8;
                prog.push(op);
                prog.push(reg);
                prog.push(rng.u8());
            }
            
            prog.push(0x03);
            prog.push(target_addr);
            prog.push(0x01);
            prog.push(mask);
            prog.push(0x07);
            prog.push(0x11);
            prog.push(target_addr);
            
            instr_id = instr_id.wrapping_add(1);
        }
        
        prog.push(0xF0);
        prog.push(half_idx as u8);
        prog.push(opaque_labels[half_idx * 32]);
        prog.push(opaque_labels[half_idx * 32 + 1]);
    }
    
    prog.push(0x00);
    prog
}

fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

fn main() {
    println!("cargo:rerun-if-changed=shared.rs");
    println!("cargo:rerun-if-changed=read.txt");

    let out_dir = std::env::var("OUT_DIR").unwrap();

    let mut salt = [0u8; ARGON2_SALT_LEN];
    getrandom(&mut salt).expect("getrandom failed");
    write_blob(&out_dir, "salt.bin", &salt);

    let password = DEFAULT_PASSWORD;

    let mut master_key = argon2id_hash(password, &salt);

    let mut bk_bytes = Vec::with_capacity(master_key.len() + b"bootstrap".len());
    bk_bytes.extend_from_slice(&master_key);
    bk_bytes.extend_from_slice(b"bootstrap");
    let mut bk = sha3_256(&bk_bytes);
    zeroize(&mut bk_bytes);

    let content = fs::read("read.txt").expect("read.txt missing at package root");

    println!("cargo:warning==== BUILD INFO ===");
    println!("cargo:warning=Plaintext chars: {}", content.len());
    let preview: String = std::str::from_utf8(&content)
        .unwrap_or("")
        .chars()
        .take(80)
        .collect();
    println!("cargo:warning=First 80 chars: {}", preview);
    let preview_end: String = std::str::from_utf8(&content)
        .unwrap_or("")
        .chars()
        .rev()
        .take(80)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    println!("cargo:warning=Last 80 chars: {}", preview_end);
    println!("cargo:warning=Plaintext SHA-3-256: {}", sha3_256(&content).iter().map(|b| format!("{:02x}", b)).collect::<String>());
    println!("cargo:warning=Argon2id: mem={}KiB iter={} parallel={}", ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM);
    println!("cargo:warning====================");

    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    let mut rng_k = Rng::new(build_seed() ^ 0xA5A5);
    rng_k.fill(&mut k1);
    let mut rng_k2 = Rng::new(build_seed() ^ 0x5A5A);
    rng_k2.fill(&mut k2);

    let inner = encrypt(&k2, b"inner", &content);
    let payload = encrypt(&k1, b"payload", &inner);
    write_blob(&out_dir, "payload.bin", &payload);

    let ts = OPEN_TIMESTAMP_UNIX_SECONDS.to_le_bytes();
    let ts_blob = encrypt(&k1, b"timestamp", &ts);
    write_blob(&out_dir, "ts.bin", &ts_blob);
    write_blob(&out_dir, "ts_plain.bin", &ts);

    let mut km = [0u8; KEY_LEN];
    let mut rng_km = Rng::new(build_seed() ^ 0x3C3C);
    rng_km.fill(&mut km);

    let vm_seed = build_seed() ^ 0xDEAD;
    let mut prog = gen_vm_program(&k1, &k2, &km, vm_seed);

    let prog_blob = encrypt(&bk, b"vmprog", &prog);
    write_blob(&out_dir, "vmprog.bin", &prog_blob);
    write_blob(&out_dir, "km.bin", &km);

    zeroize(&mut master_key);
    zeroize(&mut bk);
    zeroize(&mut k1);
    zeroize(&mut k2);
    zeroize(&mut km);
    zeroize(prog.as_mut_slice());
}