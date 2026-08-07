use std::fs;
// Print project title at build time (moved into main)

use std::io::Write;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use getrandom::getrandom;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use std::process::Command;

use std::time::UNIX_EPOCH;
use zeroize::Zeroize;


use ml_kem::{DecapsulationKey, Encapsulate, MlKem1024, KeyExport};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::EncodePrivateKey;


mod siv_mod {
    include!("src/serpent_siv.rs");
}
use siv_mod::{siv_encrypt as siv_encrypt_inner};

include!("shared.rs");

const DEFAULT_PASSWORD: &[u8] = PASSWORD;
const H1: usize = KEY_LEN / 2;
const ARGON2_MEMORY_KIB: u32 = 1024;
const ARGON2_ITERATIONS: u32 = 1;
const ARGON2_PARALLELISM: u32 = 1;
const ARGON2_SALT_LEN: usize = 32;
const ARGON2_OUTPUT_LEN: usize = 32;

fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().into()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
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
    // Print project title at build time
    println!("hello_old — Time-Gated Decryption Binary");
    println!("cargo:rerun-if-changed=shared.rs");
    println!("cargo:rerun-if-changed=read.txt");
    println!("cargo:rerun-if-changed=src/serpent_siv.rs");

    let out_dir = std::env::var("OUT_DIR").unwrap();

    let mut salt = [0u8; ARGON2_SALT_LEN];
    getrandom(&mut salt).expect("getrandom failed");
    write_blob(&out_dir, "salt.bin", &salt);

    let password = DEFAULT_PASSWORD;

    // [Algorithm 1] Argon2id: passphrase -> K0 (the master key).
    let mut master_key = argon2id_hash(password, &salt);

    let mut bk_bytes = Vec::with_capacity(master_key.len() + b"bootstrap".len());
    bk_bytes.extend_from_slice(&master_key);
    bk_bytes.extend_from_slice(b"bootstrap");
    let mut bk = sha3_256(&bk_bytes);
    zeroize(&mut bk_bytes);

    let content = fs::read("read.txt").expect("read.txt missing at package root");
    // Gather file metadata
    let meta = fs::metadata("read.txt").expect("metadata missing");
    let modified = meta.modified().expect("modified time error")
        .duration_since(UNIX_EPOCH).expect("time error").as_secs();
    let created = meta.created().unwrap_or_else(|_| meta.modified().expect("modified time error"))
        .duration_since(UNIX_EPOCH).expect("time error").as_secs();
    // Get last commit author for read.txt
    let author_output = Command::new("git")
        .args(&["log", "-1", "--format=%an", "read.txt"])
        .output()
        .expect("git command failed");
    let author = String::from_utf8_lossy(&author_output.stdout).trim().to_string();
    // Build metadata JSON
    let meta_json = format!(r#"{{"created":{},"modified":{},"author":"{}"}}"#, created, modified, author);
    let meta_bytes = meta_json.as_bytes();
    let meta_len = meta_bytes.len() as u32;
    // Construct payload: [meta_len][meta_bytes][original content]
    let mut payload = Vec::with_capacity(4 + meta_bytes.len() + content.len());
    payload.extend_from_slice(&meta_len.to_le_bytes());
    payload.extend_from_slice(meta_bytes);
    payload.extend_from_slice(&content);
    // Simulate encryption progress bar
    let total_steps = 10;
    for step in 0..=total_steps {
        let percent = step * 100 / total_steps;
        let bar = "#".repeat(step as usize);
        print!("\rEncrypting payload: [{:<10}] {}%", bar, percent);
        std::io::stdout().flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    println!();

    // Generate k1 and k2 first (needed for payload encryption)
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    let mut rng_k = Rng::new(build_seed() ^ 0xA5A5);
    rng_k.fill(&mut k1);
    let mut rng_k2 = Rng::new(build_seed() ^ 0x5A5A);
    rng_k2.fill(&mut k2);

    // Double-wrap the payload for runtime: k1 then k2
    let mut inner = wrap_key(&k1, b"inner", &payload);
    let mut double_wrapped = wrap_key(&k2, b"payload", &inner);

    let plaintext_hash = sha3_256(&payload);
    // Write the encrypted payload with metadata to output
    write_blob(&out_dir, "payload.bin", &double_wrapped);
    // Zeroize payload after writing
    zeroize(&mut payload);
    zeroize(&mut inner);
    zeroize(&mut double_wrapped);

    let mut rng = rand::rngs::OsRng;

    // ---- KDF key (KEK) recovery path: RustyVM(master, kmaterial) -> k1||k2 ----
    let mut kek = [0u8; 64];
    kek[..32].copy_from_slice(&k1);
    kek[32..].copy_from_slice(&k2);

    let ts = OPEN_TIMESTAMP_UNIX_SECONDS.to_le_bytes();
    let ts_blob = wrap_key(&k1, b"timestamp", &ts);
    write_blob(&out_dir, "ts.bin", &ts_blob);
    write_blob(&out_dir, "ts_plain.bin", &ts);

    let mut km = [0u8; KEY_LEN];
    let mut rng_km = Rng::new(build_seed() ^ 0x3C3C);
    rng_km.fill(&mut km);

    let vm_seed = build_seed() ^ 0xDEAD;
    let mut prog = gen_vm_program(&k1, &k2, &km, vm_seed);

    let prog_blob = wrap_key(&bk, b"vmprog", &prog);
    write_blob(&out_dir, "vmprog.bin", &prog_blob);
    write_blob(&out_dir, "km.bin", &km);
    write_blob(&out_dir, "salt.bin", &salt);
    zeroize(&mut master_key);
    zeroize(&mut bk);

    // The KEK (k1||k2) is the password-derived key that wraps every KEM secret key.
    let mut kek_key: [u8; 32] = {
        let mut kk = [0u8; 32];
        kk.copy_from_slice(&kek[..32]);
        kk
    };

    println!("cargo:warning===== BUILD INFO ====");
    println!("cargo:warning=Plaintext chars: {}", content.len());
    println!("cargo:warning=Plaintext SHA-3-256: {}", hex(&plaintext_hash));
    println!(
        "cargo:warning=Algorithms: Argon2id + RSA-4096-OAEP + Kyber-1024 + McEliece-6960119f + Serpent-256-SIV + Ed448ph + Seccomp-BPF"
    );
    println!("cargo:warning=KDF/KEK (Argon2id->RustyVM): {:02x?}", &kek[..8]);
    zeroize(&mut kek);

    // ---- [Algorithm 2] RSA-4096: generate keypair, wrap a shared shard ----
    let rsa_sk = RsaPrivateKey::new(&mut rng, 4096).expect("rsa keygen");
    let rsa_pk = RsaPublicKey::from(&rsa_sk);
    let rsa_der = rsa_sk
        .to_pkcs8_der()
        .expect("rsa pkcs8 der")
        .as_bytes()
        .to_vec();
    write_blob(&out_dir, "rsa_sk_wrap.bin", &wrap_key(&kek_key, b"rsa-sk", &rsa_der));

    let mut s_rsa = [0u8; 32];
    getrandom(&mut s_rsa).expect("getrandom failed");
    let oaep = Oaep::new_with_mgf_hash::<Sha256, Sha256>();
    let ct_rsa = rsa_pk
        .encrypt(&mut rng, oaep, &s_rsa)
        .expect("rsa oaep encrypt");
    write_blob(&out_dir, "ct_rsa.bin", &ct_rsa);
    println!("cargo:warning=RSA-4096: ct={} der={} bits=4096", ct_rsa.len(), rsa_der.len());

    // ---- [Algorithm 3] Kyber-1024: keypair + encapsulation ----
    let dk_ky = DecapsulationKey::<MlKem1024>::generate();
    let ek_ky = dk_ky.encapsulation_key();
    let (ct_ky, sh_ky) = ek_ky.encapsulate();
    let dk_ky_bytes: Vec<u8> = dk_ky.to_bytes().as_slice().to_vec();
    write_blob(&out_dir, "ky_sk_wrap.bin", &wrap_key(&kek_key, b"ky-sk", &dk_ky_bytes));
    write_blob(&out_dir, "ct_ky.bin", ct_ky.as_slice());
    let mut s_ky = [0u8; 32];
    s_ky.copy_from_slice(sh_ky.as_slice());
    println!(
        "cargo:warning=Kyber-1024: ct={} shard recovered",
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
        &wrap_key(&kek_key, b"mce-sk", &sk_mce_bytes),
    );
    let ct_mce_arr: [u8; mc::CRYPTO_CIPHERTEXTBYTES] = *ct_mce.as_array();
    write_blob(&out_dir, "ct_mce.bin", &ct_mce_arr);
    let mut s_mce = [0u8; 32];
    s_mce.copy_from_slice(sh_mce.as_array());
    println!(
        "cargo:warning=McEliece-6960119f: pubkey={} sk={} ct={} shard recovered",
        pub_mce.as_ref().len(),
        sk_mce_bytes.len(),
        ct_mce.as_array().len()
    );

    // ---- The three 32-byte shards XOR into the 256-bit Serpent DEK ----
    let mut dek = xor32(&s_rsa, &s_ky, &s_mce);

    // ---- [Algorithm 5] Serpent-256-SIV: authenticated encryption of the payload ----
    let siv_blob = siv_encrypt_inner(&dek, &ts, &content);
    write_blob(&out_dir, "serpent_siv.bin", &siv_blob);
    // Store ciphertext length for display / parsing.
    let siv_len = (siv_blob.len() as u32).to_le_bytes();
    write_blob(&out_dir, "serpent_siv_len.bin", &siv_len);

    // ---- [Algorithm 6] Ed448: sign the binding message ----
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
    println!(
        "cargo:warning=Ed448: vk=57B sig=114B over (ts|dek|sha256(siv)) signed",
    );

    println!("cargo:warning=Serpent-256-SIV: blob={} (V(16) || ct)", siv_blob.len());
    println!("cargo:warning=DEK shards XOR combined (32B) = {:02x?}", &dek[..8]);
    println!("cargo:warning=Message signed (timestamp+DEK+hash) with Ed448");
    println!("cargo:warning====================");

    // Sensitive material cleanup.
    zeroize(&mut s_rsa);
    zeroize(&mut s_ky);
    zeroize(&mut s_mce);
    zeroize(&mut dek);
    zeroize(&mut kek_key);
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
