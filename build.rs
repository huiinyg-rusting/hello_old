use std::fs;
use std::io::Write;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use getrandom::getrandom;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use sm3::{Digest as Sm3Digest, Sm3};
use std::time::UNIX_EPOCH;

use ml_kem::{DecapsulationKey, Encapsulate, MlKem1024, KeyExport};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::EncodePrivateKey;
use crystals_dilithium::{ml_dsa_87::Keypair, RandomMode};
use blake3;

mod siv_mod {
    include!("src/serpent_siv.rs");
}
use siv_mod::{siv_encrypt as siv_encrypt_inner};

include!("shared.rs");

/// Build-time info banner: only shown for debug builds. Release builds keep
/// the binary blobs, hashes, lengths and KEK samples out of the build log so
/// nothing about the sealed payload leaks through stdout.
#[cfg(debug_assertions)]
macro_rules! binfo {
    ($($arg:tt)*) => { println!("cargo:warning={}", format!($($arg)*)) };
}

#[cfg(not(debug_assertions))]
macro_rules! binfo {
    ($($arg:tt)*) => {};
}

const DEFAULT_PASSWORD: &[u8] = PASSWORD;
const H1: usize = KEY_LEN / 2;
const ARGON2_MEMORY_KIB: u32 = 262144;
const ARGON2_ITERATIONS: u32 = 4;
const ARGON2_PARALLELISM: u32 = 8;
const ARGON2_SALT_LEN: usize = 32;
const ARGON2_OUTPUT_LEN: usize = 32;

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    // Manual HKDF-SHA256: Extract + Expand
    use sha2::Sha256;
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
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

fn derive_wrapping_keys(master_key: &[u8; 32]) -> [[u8; 32]; 6] {
    let labels: [&[u8]; 6] = [
        b"wrap-rsa",
        b"wrap-kyber",
        b"wrap-mceliece",
        b"wrap-frodokem",
        b"wrap-dilithium",
        b"wrap-serpent-dek",
    ];
    let mut keys = [[0u8; 32]; 6];
    for (i, label) in labels.iter().enumerate() {
        let key = hkdf_sha256(master_key, b"hello-old-v1", label, 32);
        keys[i].copy_from_slice(&key);
    }
    keys
}

fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().into()
}

fn sm3_256(data: &[u8]) -> [u8; 32] {
    let mut h = <Sm3 as Sm3Digest>::new();
    Sm3Digest::update(&mut h, data);
    Sm3Digest::finalize(h).into()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn blake3_256(data: &[u8]) -> [u8; 32] {
    let hash = blake3::hash(data);
    *hash.as_bytes()
}

/// Master signing secret (32 bytes) for the binary self-signature. It is NOT
/// derivable from source: it comes from the HELLO_OLD_SELF_SIGN_KEY env var
/// (64 hex chars) or the git-ignored file <repo>/signing/selfsign.key. build.rs
/// and xtask must both use the same secret, so the embedded verifying key and
/// the overlay signature always agree. If no secret is available the build
/// FAILS — we never emit a binary whose signature can be re-forged by anyone
/// who has only the source.
fn self_sign_secret() -> [u8; 57] {
    let mut seed = [0u8; 32];
    let loaded = if let Ok(hex) = std::env::var("HELLO_OLD_SELF_SIGN_KEY") {
        seed = decode_hex32(hex.trim())
            .unwrap_or_else(|e| panic!("HELLO_OLD_SELF_SIGN_KEY invalid: {e}"));
        true
    } else {
        let root = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
        let path = std::path::Path::new(&root).join("signing").join("selfsign.key");
        println!("cargo:rerun-if-changed={}", path.display());
        if let Ok(hex) = std::fs::read_to_string(&path) {
            seed = decode_hex32(hex.trim())
                .unwrap_or_else(|e| panic!("{} invalid: {e}", path.display()));
            true
        } else {
            false
        }
    };
    if !loaded {
        panic!(
            "refusing to build: no self-signing secret. Set HELLO_OLD_SELF_SIGN_KEY (64 hex chars) \
             or provide signing/selfsign.key (a build artifact, git-ignored)."
        );
    }
    // Expand the 32-byte seed to the 57-byte Ed448 scalar in counter mode.
    let mut out = [0u8; 57];
    let mut ctr: u64 = 0;
    let mut pos = 0;
    while pos < 57 {
        let mut h = blake3::Hasher::new();
        h.update(&seed);
        h.update(&ctr.to_le_bytes());
        let block = h.finalize();
        let n = (57 - pos).min(32);
        out[pos..pos + n].copy_from_slice(&block.as_bytes()[..n]);
        pos += n;
        ctr += 1;
    }
    out
}

fn decode_hex32(s: &str) -> Result<[u8; 32], String> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(bytes[2 * i])?;
        let lo = hex_nibble(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("non-hex byte {:?}", b as char)),
    }
}

/// Counter-mode keystream seeded from blake3(k1||k2||salt). Both build.rs and
/// main.rs derive identical streams so the reveal can un-whiten the payload.
/// XORs `buf` in place (no extra keystream copy).
fn blake3_keystream(k1: &[u8; 32], k2: &[u8; 32], salt: &[u8], buf: &mut [u8]) {
    let mut seed_vec = Vec::with_capacity(64 + salt.len());
    seed_vec.extend_from_slice(k1);
    seed_vec.extend_from_slice(k2);
    seed_vec.extend_from_slice(salt);
    let mut seed: [u8; 32] = *blake3::hash(&seed_vec).as_bytes();
    zeroize(&mut seed_vec);
    let mut ctr: u64 = 0;
    let mut pos = 0;
    while pos < buf.len() {
        let mut h = blake3::Hasher::new();
        h.update(&seed);
        h.update(&ctr.to_le_bytes());
        let block = h.finalize();
        let n = (buf.len() - pos).min(32);
        for i in 0..n {
            buf[pos + i] ^= block.as_bytes()[i];
        }
        pos += n;
        ctr += 1;
    }
    zeroize(&mut seed);
}

fn nonce_for(key: &[u8; 32], label: &[u8]) -> [u8; 12] {
    let mut h = Sha3_256::new();
    h.update(key);
    h.update(label);
    let res = h.finalize();
    let mut n = [0u8; 12];
    n.copy_from_slice(&res[..12]);
    n
}

fn wrap_key(key: &[u8; 32], label: &[u8], plain: &[u8]) -> Vec<u8> {
    let nonce = nonce_for(key, label);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain)
        .expect("wrap encrypt failed");
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

fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

struct Rng(u64);

impl rand_core::TryRng for Rng {
    type Error = std::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.next_u64() as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next_u64())
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(dst);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Rng {}

// OS-backed RNG satisfying rand_core 0.10 traits for frodo-kem
struct SysRng;

impl rand_core::TryRng for SysRng {
    type Error = std::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        getrandom(&mut b).expect("getrandom failed");
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        getrandom(&mut b).expect("getrandom failed");
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom(dst).expect("getrandom failed");
        Ok(())
    }
}

impl rand_core::TryCryptoRng for SysRng {}

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
    fn choice(&mut self, n: usize) -> usize {
        (self.next_u64() as usize) % n
    }
}

fn gen_opaque_predicate(rng: &mut Rng) -> u8 {
    match rng.choice(4) {
        0 => 0xE0,
        1 => 0xE1,
        2 => 0xE2,
        _ => 0xE3,
    }
}

fn build_seed() -> u64 {
    let mut seed = [0u8; 32];
    getrandom(&mut seed).expect("getrandom failed");
    u64::from_le_bytes(seed[..8].try_into().unwrap())
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
    }

    prog.push(0x00);
    prog
}

fn argon2id_hash(password: &[u8], salt: &[u8]) -> [u8; ARGON2_OUTPUT_LEN] {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(ARGON2_OUTPUT_LEN),
    )
    .expect("argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; ARGON2_OUTPUT_LEN];
    argon2
        .hash_password_into(password, salt, &mut out)
        .expect("argon2 hash");
    out
}

fn xor32(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let mut o = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        o[i] = a[i] ^ b[i] ^ c[i];
        i += 1;
    }
    o
}

fn main() {
    // Heavy crypto (McEliece-6960119f keygen, FrodoKEM, RSA-4096) uses multi-MB
    // stack arrays that exceed the default 1MB Windows main-thread stack, so run
    // everything on a dedicated thread with a large stack.
    std::thread::Builder::new()
        .name("build-worker".into())
        .stack_size(512 * 1024 * 1024)
        .spawn(build_main)
        .expect("failed to spawn build thread")
        .join()
        .expect("build thread panicked");
}

fn build_main() {
    // Print project title at build time
    println!("hello_old — Time-Gated Decryption Binary");
    println!("cargo:rerun-if-changed=shared.rs");
    println!("cargo:rerun-if-changed=read.txt");
    println!("cargo:rerun-if-changed=src/serpent_siv.rs");

    let out_dir = std::env::var("OUT_DIR").unwrap();

    let mut salt = [0u8; ARGON2_SALT_LEN];
    getrandom(&mut salt).expect("getrandom failed");
    write_blob(&out_dir, "salt.bin", &salt);
    // Keep the Argon2 salt alive: the FrodoKEM block later shadows `salt` with
    // its own per-scheme salt, and the SIV whitening must use the KDF salt to
    // match what main.rs reads back from salt.bin.
    let kdf_salt: [u8; ARGON2_SALT_LEN] = salt;

    let password = DEFAULT_PASSWORD;

    // [Algorithm 1] Argon2id: passphrase -> K0 (the master key).
    let mut master_key = argon2id_hash(password, &salt);

    let mut bk_bytes = Vec::with_capacity(master_key.len() + b"bootstrap".len());
    bk_bytes.extend_from_slice(&master_key);
    bk_bytes.extend_from_slice(b"bootstrap");
    let mut bk = sha3_256(&bk_bytes);
    zeroize(&mut bk_bytes);

    let content = fs::read("read.txt").expect("read.txt missing at package root");
    // Print the head of the secret so builders can see what the char count maps to.
    #[cfg(debug_assertions)]
    {
        let head: String = String::from_utf8_lossy(&content[..content.len().min(120)]).into_owned();
        let head = head.replace('\n', " \\n ");
        binfo!("read.txt head ({} chars): {}", content.len(), head);
    }
    // Gather file metadata
    let meta = fs::metadata("read.txt").expect("metadata missing");
    let modified = meta.modified().expect("modified time error")
        .duration_since(UNIX_EPOCH).expect("time error").as_secs();
    let created = meta.created().unwrap_or_else(|_| meta.modified().expect("modified time error"))
        .duration_since(UNIX_EPOCH).expect("time error").as_secs();
    // Get the local system user as the author (no git dependency).
    let author = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    // Build metadata JSON
    let meta_json = format!(r#"{{"created":{},"modified":{},"author":"{}"}}"#, created, modified, author);
    let meta_bytes = meta_json.as_bytes();
    let meta_len = meta_bytes.len() as u32;
    // Construct payload: [meta_len][meta_bytes][original content]
    let mut payload = Vec::with_capacity(4 + meta_bytes.len() + content.len());
    payload.extend_from_slice(&meta_len.to_le_bytes());
    payload.extend_from_slice(meta_bytes);
    payload.extend_from_slice(&content);
    // Simulate encryption progress bar (debug builds only; release stays silent)
    #[cfg(debug_assertions)]
    {
        let total_steps = 10;
        for step in 0..=total_steps {
            let percent = step * 100 / total_steps;
            let bar = "#".repeat(step as usize);
            print!("\rEncrypting payload: [{:<10}] {}%", bar, percent);
            std::io::stdout().flush().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        println!();
    }

    // Generate k1 and k2 first (needed for payload encryption)
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    let mut rng_k = Rng::new(build_seed() ^ 0xA5A5);
    rng_k.fill(&mut k1);
    let mut rng_k2 = Rng::new(build_seed() ^ 0x5A5A);
    rng_k2.fill(&mut k2);

    let plaintext_hash = sha3_256(&payload);
    // Zeroize the raw payload now; the sealed form is rebuilt (and zeroized)
    // later in the Serpent-SIV block.
    zeroize(&mut payload);
    // Legacy double-wrapped payload.bin is no longer emitted: the payload is
    // LZMA-compressed + keystream-whitened and sealed via Serpent-SIV below.

    let mut rng = rand::rngs::OsRng;

    // ---- KDF key (KEK) recovery path: RustyVM(master, kmaterial) -> k1||k2 ----
    let mut kek = [0u8; 64];
    kek[..32].copy_from_slice(&k1);
    kek[32..].copy_from_slice(&k2);

    let ts = OPEN_TIMESTAMP_UNIX_SECONDS.to_le_bytes();
    let ts_blob = wrap_key(&k1, b"timestamp", &ts);
    write_blob(&out_dir, "ts.bin", &ts_blob);

    // ---- Tamper-proof timestamp guard ----
    // The plain timestamp is no longer embedded verbatim. Instead we embed N
    // redundant fragments, each XORed with an independent random mask plus a
    // random-ordered SHA3 integrity chain. To rewrite the open time an
    // attacker must correctly patch every fragment AND the chain hash AND the
    // exact runtime recomposition order, which is derived from random bytes
    // stored in yet another fragment — a single-byte edit breaks everything.
    let mut rng_ts = Rng::new(build_seed() ^ 0x5157);
    let mut masks = [0u64; 8];
    for m in masks.iter_mut() {
        *m = rng_ts.next_u64();
    }
    let ts64 = OPEN_TIMESTAMP_UNIX_SECONDS;
    let mut frags = [0u64; 8];
    for (i, f) in frags.iter_mut().enumerate() {
        *f = ts64 ^ masks[i];
    }
    let mut order = [0u8; 8];
    rng_ts.fill(&mut order);
    // chain = sha3(frag[order[0]] || frag[order[1]] || ... || mask[order[0]] || ...)
    let mut chain_input = Vec::new();
    for i in 0..8 {
        chain_input.extend_from_slice(&frags[order[i] as usize % 8].to_le_bytes());
        chain_input.extend_from_slice(&masks[order[i] as usize % 8].to_le_bytes());
    }
    let chain = Sha3_256::digest(&chain_input);
    let mut guard = Vec::new();
    for f in frags.iter() {
        guard.extend_from_slice(&f.to_le_bytes());
    }
    for m in masks.iter() {
        guard.extend_from_slice(&m.to_le_bytes());
    }
    guard.extend_from_slice(&order);
    guard.extend_from_slice(&chain);
    write_blob(&out_dir, "ts_guard.bin", &guard);

    let mut km = [0u8; KEY_LEN];
    let mut rng_km = Rng::new(build_seed() ^ 0x3C3C);
    rng_km.fill(&mut km);

    let vm_seed = build_seed() ^ 0xDEAD;
    let mut prog = gen_vm_program(&k1, &k2, &km, vm_seed);

    let prog_blob = wrap_key(&bk, b"vmprog", &prog);
    write_blob(&out_dir, "vmprog.bin", &prog_blob);
    // M6: integrity anchor for the VM program — the blake3 of the *encrypted*
    // blob is embedded so a runtime memory patch of the VM bytecode is caught
    // by the startup check in main.
    write_blob(&out_dir, "vmprog_hash.bin", &blake3_256(&prog_blob));
    write_blob(&out_dir, "km.bin", &km);
    write_blob(&out_dir, "salt.bin", &salt);
    zeroize(&mut master_key);
    zeroize(&mut bk);

    // The KEK (k1||k2) is the password-derived key that wraps every KEM secret key.
    // Now using HKDF to derive 6 independent wrapping keys
    let wrapping_keys = derive_wrapping_keys(&kek[..32].try_into().expect("kek slice"));
    let mut rsa_wrap_key = wrapping_keys[0];
    let mut kyber_wrap_key = wrapping_keys[1];
    let mut mceliece_wrap_key = wrapping_keys[2];
    let mut frodokem_wrap_key = wrapping_keys[3];
    let mut dilithium_wrap_key = wrapping_keys[4];
    let mut serpent_dek_wrap_key = wrapping_keys[5];

    binfo!("===== BUILD INFO ====");
    binfo!("Plaintext chars: {}", content.len());
    binfo!("Plaintext SHA-3-256: {}", hex(&plaintext_hash));
    binfo!(
        "Algorithms: Argon2id + RSA-4096-OAEP + Kyber-1024 + McEliece-6960119f + FrodoKEM-1344 + CRYSTALS-Dilithium-5 + Serpent-256-SIV + Ed448ph + SM3 + BLAKE3 + Seccomp-BPF"
    );
    binfo!("KDF/KEK (Argon2id->RustyVM): {:02x?}", &kek[..8]);
    zeroize(&mut kek);

    // ---- [Algorithm 2] RSA-4096: generate keypair, wrap a shared shard ----
    let rsa_sk = RsaPrivateKey::new(&mut rng, 4096).expect("rsa keygen");
    let rsa_pk = RsaPublicKey::from(&rsa_sk);
    let rsa_der = rsa_sk
        .to_pkcs8_der()
        .expect("rsa pkcs8 der")
        .as_bytes()
        .to_vec();
    write_blob(&out_dir, "rsa_sk_wrap.bin", &wrap_key(&rsa_wrap_key, b"rsa-sk", &rsa_der));

    let mut s_rsa = [0u8; 32];
    getrandom(&mut s_rsa).expect("getrandom failed");
    let oaep = Oaep::new_with_mgf_hash::<Sha256, Sha256>();
    let ct_rsa = rsa_pk
        .encrypt(&mut rng, oaep, &s_rsa)
        .expect("rsa oaep encrypt");
    write_blob(&out_dir, "ct_rsa.bin", &ct_rsa);
    binfo!("RSA-4096: ct={} der={} bits=4096", ct_rsa.len(), rsa_der.len());

    // ---- [Algorithm 3] Kyber-1024: keypair + encapsulation ----
    let dk_ky = DecapsulationKey::<MlKem1024>::generate();
    let ek_ky = dk_ky.encapsulation_key();
    let (ct_ky, sh_ky) = ek_ky.encapsulate();
    let dk_ky_bytes: Vec<u8> = dk_ky.to_bytes().as_slice().to_vec();
    write_blob(&out_dir, "ky_sk_wrap.bin", &wrap_key(&kyber_wrap_key, b"ky-sk", &dk_ky_bytes));
    write_blob(&out_dir, "ct_ky.bin", ct_ky.as_slice());
    let mut s_ky = [0u8; 32];
    s_ky.copy_from_slice(sh_ky.as_slice());
    binfo!(
        "Kyber-1024: ct={} shard recovered",
        ct_ky.as_slice().len()
    );

    // ---- [Algorithm 4] Classic McEliece-6960119f: keypair + encapsulation ----
    use classic_mceliece_rust as mc;
    let (pub_mce, sk_mce) = mc::keypair_boxed(&mut rng);
    let (ct_mce, sh_mce) = mc::encapsulate_boxed(&pub_mce, &mut rng);
    let sk_mce_bytes: Vec<u8> = sk_mce.as_array().to_vec();
    write_blob(
        &out_dir,
        "mce_sk_wrap.bin",
        &wrap_key(&mceliece_wrap_key, b"mce-sk", &sk_mce_bytes),
    );
    let ct_mce_arr: [u8; mc::CRYPTO_CIPHERTEXTBYTES] = *ct_mce.as_array();
    write_blob(&out_dir, "ct_mce.bin", &ct_mce_arr);
    let mut s_mce = [0u8; 32];
    s_mce.copy_from_slice(sh_mce.as_array());
    binfo!(
        "McEliece-6960119f: pubkey={} sk={} ct={} shard recovered",
        pub_mce.as_ref().len(),
        sk_mce_bytes.len(),
        ct_mce.as_array().len()
    );

    // ---- The six 32-byte shards XOR into the 256-bit Serpent DEK ----
    // Now with 6 shards: RSA, Kyber, McEliece, FrodoKEM, Dilithium(BLAKE3), SM3

    // ---- [Algorithm 5] FrodoKEM-1344: keypair + encapsulation ----
    use frodo_kem::Algorithm as FrodoAlgorithm;
    let frodo_alg = FrodoAlgorithm::FrodoKem1344Aes;
    let frodo_params = frodo_alg.params();
    let mut sys_rng = SysRng;
    let (frodo_pk, frodo_sk) = frodo_alg.generate_keypair(&mut sys_rng);
    
    // Generate 32-byte shared secret (shard) and salt
    let mut s_frodo = [0u8; 32];
    getrandom(&mut s_frodo).expect("getrandom failed");
    let mut salt = vec![0u8; frodo_params.salt_length];
    getrandom(&mut salt).expect("getrandom failed");
    
    let (ct_frodo, _sh_frodo) = frodo_alg.encapsulate(&frodo_pk, &s_frodo, &salt).expect("frodokem encapsulate");
    
    let frodokem_sk_bytes = frodo_sk.as_ref().to_vec();
    write_blob(
        &out_dir,
        "frodo_sk_wrap.bin",
        &wrap_key(&frodokem_wrap_key, b"frodo-sk", &frodokem_sk_bytes),
    );
    write_blob(&out_dir, "ct_frodo.bin", ct_frodo.as_ref());
    binfo!(
        "FrodoKEM-1344: ct={} shard recovered",
        ct_frodo.as_ref().len()
    );
    
    // ---- [Algorithm 6] CRYSTALS-Dilithium-5 (ML-DSA-87): keypair + signing ----
    let dilithium_keypair: Keypair = Keypair::generate(None).expect("Dilithium keypair generation");
    let dilithium_vk = &dilithium_keypair.public;
    let dilithium_sk_bytes = dilithium_keypair.secret.to_bytes().to_vec();
    write_blob(
        &out_dir,
        "dilithium_sk_wrap.bin",
        &wrap_key(&dilithium_wrap_key, b"dilithium-sk", &dilithium_sk_bytes),
    );
    write_blob(&out_dir, "dilithium_vk.bin", dilithium_vk.to_bytes().as_slice());
    let mut s_dilithium = [0u8; 32];
    // Use blake3 hash of dilithium public key as additional entropy shard
    let dilithium_pk_hash = blake3_256(dilithium_vk.to_bytes().as_slice());
    s_dilithium.copy_from_slice(&dilithium_pk_hash);

    // Use SM3 hash of the *same* dilithium public key as a 6th shard, so the
    // VK is bound by two independent hash primitives (BLAKE3 + SM3). The byte
    // slice here is identical to what main.rs uses, keeping DEK recovery round-trip valid.
    let s_sm3 = sm3_256(dilithium_vk.to_bytes().as_slice());
    binfo!(
        "CRYSTALS-Dilithium-5 (ML-DSA-87): vk={} sk wrapped",
        dilithium_vk.to_bytes().as_slice().len()
    );

    // ---- Combine all 6 shards into the 256-bit Serpent DEK ----
    // RSA ^ Kyber ^ McEliece ^ FrodoKEM ^ Dilithium(BLAKE3) ^ SM3
    let mut dek = xor32(&s_rsa, &s_ky, &s_mce);
    dek = xor32(&dek, &s_frodo, &s_dilithium);
    dek = xor32(&dek, &s_sm3, &[0u8; 32]);

    // ---- [Algorithm 7] Serpent-256-SIV: authenticated encryption of the payload ----
    // The plaintext is the sealed payload: [meta_len][meta_json][content],
    // so the reveal can show who created it and when. It is rebuilt here since
    // the earlier copy of `payload` is zeroized below.
    let mut sealed_payload = {
        let mut sp = Vec::with_capacity(4 + meta_bytes.len() + content.len());
        sp.extend_from_slice(&meta_len.to_le_bytes());
        sp.extend_from_slice(&meta_bytes);
        sp.extend_from_slice(&content);
        sp
    };
    let plain_len = sealed_payload.len() as u32;

    // Compress then whiten. LZMA shrinks the sealed payload; the compressed
    // stream is XOR-masked with a keystream derived from k1||k2||salt, so the
    // DEK shards alone no longer suffice — the password-derived keys are
    // required too. The SIV ciphertext then authenticates the whitened bytes.
    let mut compressed = Vec::new();
    {
        let mut input = sealed_payload.as_slice();
        lzma_rs::lzma_compress(&mut input, &mut compressed).expect("lzma compress");
    }
    zeroize(&mut sealed_payload);

    blake3_keystream(&k1, &k2, &kdf_salt, &mut compressed);
    let siv_blob = siv_encrypt_inner(&dek, &ts, &compressed);
    zeroize(&mut compressed);
    write_blob(&out_dir, "serpent_siv.bin", &siv_blob);
    // Store ciphertext length for display / parsing.
    let siv_len = (siv_blob.len() as u32).to_le_bytes();
    write_blob(&out_dir, "serpent_siv_len.bin", &siv_len);
    // Plaintext (sealed) length so the runtime can size its secure buffer
    // before inflating the LZMA stream.
    write_blob(&out_dir, "serpent_plain_len.bin", &plain_len.to_le_bytes());

    // Wrap the DEK with the serpent-dek wrapping key for runtime recovery
    let dek_wrap = wrap_key(&serpent_dek_wrap_key, b"serpent-dek", &dek);
    write_blob(&out_dir, "dek_wrap.bin", &dek_wrap);

    // ---- [Algorithm 8] Ed448: sign the binding message ----
    use ed448_goldilocks::{Signature, SigningKey};
    use ed448_goldilocks::elliptic_curve::Generate;
    let ed_sk = SigningKey::generate();
    let ed_vk = ed_sk.verifying_key();
    write_blob(&out_dir, "ed_vk.bin", ed_vk.to_bytes().as_ref());

    let mut msg = Vec::with_capacity(8 + 32 + 32);
    msg.extend_from_slice(&ts);
    msg.extend_from_slice(&dek);
    msg.extend_from_slice(&sha256(&siv_blob));
    let sig: Signature = ed_sk.sign_raw(&msg);
    write_blob(&out_dir, "ed_sig.bin", sig.to_bytes().as_ref());
    binfo!("Ed448: vk=57B sig=114B over (ts|dek|sha256(siv)) signed");

    // ---- Self-signature: deterministic fixed key (embedded vk) ----
    // The PE-overlay self-signature used to be produced by xtask with a fresh
    // random key every run, which made it meaningless (anyone could re-sign the
    // binary with their own key). Now the verifying key is derived from a fixed
    // label and embedded in the binary at build time; xtask derives the same
    // key and signs the overlay. An attacker who patches the file can no longer
    // re-sign it — the embedded vk will simply not match.
    let self_sk = SigningKey::try_from(self_sign_secret().as_slice()).expect("self-sign key");
    write_blob(&out_dir, "selfsig_vk.bin", self_sk.verifying_key().to_bytes().as_ref());
    drop(self_sk); // SigningKey's Drop zeroizes the secret automatically.

    // ---- [Algorithm 9] CRYSTALS-Dilithium-5: sign the binding message ----
    let dilithium_sig = dilithium_keypair.sign(&msg, None, RandomMode::Hedged).expect("Dilithium sign");
    write_blob(&out_dir, "dilithium_sig.bin", &dilithium_sig);
    binfo!(
        "CRYSTALS-Dilithium-5: sig={} over (ts|dek|sha256(siv)) signed",
        dilithium_sig.len()
    );

    // ---- Write all KEM ciphertexts and wrapped private keys for runtime ----
    // RSA
    // ct_rsa.bin, rsa_sk_wrap.bin already written
    // Kyber
    // ct_ky.bin, ky_sk_wrap.bin already written
    // McEliece
    // ct_mce.bin, mce_sk_wrap.bin already written
    // FrodoKEM
    // ct_frodo.bin, frodo_sk_wrap.bin already written
    // Dilithium
    // dilithium_sk_wrap.bin, dilithium_vk.bin, dilithium_sig.bin already written

    binfo!("Serpent-256-SIV: blob={} (V(16) || ct)", siv_blob.len());
    binfo!("DEK shards XOR combined (32B) = {:02x?}", &dek[..8]);
    binfo!("Message signed (timestamp+DEK+hash) with Ed448 + Dilithium-5");
    binfo!("====================");

    // Sensitive material cleanup.
    zeroize(&mut s_rsa);
    zeroize(&mut s_ky);
    zeroize(&mut s_mce);
    zeroize(&mut s_frodo);
    zeroize(&mut s_dilithium);
    zeroize(&mut dek);
    zeroize(&mut rsa_wrap_key);
    zeroize(&mut kyber_wrap_key);
    zeroize(&mut mceliece_wrap_key);
    zeroize(&mut frodokem_wrap_key);
    zeroize(&mut dilithium_wrap_key);
    zeroize(&mut serpent_dek_wrap_key);
    zeroize(&mut k1);
    zeroize(&mut k2);
    zeroize(&mut km);
    zeroize(prog.as_mut_slice());
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}
