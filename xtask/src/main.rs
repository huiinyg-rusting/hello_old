use std::fs;
use std::path::PathBuf;

use ed448_goldilocks::{Signature, SigningKey};

const MAGIC: &[u8; 8] = b"HLDLSIG1";
const SIG_FMT_LEN: usize = 8 + 8 + 57 + 114;

/// Deterministic 57-byte Ed448 secret, identical to build.rs so the embedded
/// verifying key (selfsig_vk.bin) matches what this tool signs with. Keep in
/// sync with build.rs::self_sign_secret().
fn self_sign_secret() -> [u8; 57] {
    let label = b"hello-old/self-sign-v1";
    let mut out = [0u8; 57];
    let mut ctr: u64 = 0;
    let mut pos = 0;
    while pos < 57 {
        let mut h = blake3::Hasher::new();
        h.update(label);
        h.update(&ctr.to_le_bytes());
        let block = h.finalize();
        let n = (57 - pos).min(32);
        out[pos..pos + n].copy_from_slice(&block.as_bytes()[..n]);
        pos += n;
        ctr += 1;
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let exe = match args.get(1) {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: cargo run --manifest-path xtask/Cargo.toml -- <exe-path> [out-path]");
            std::process::exit(2);
        }
    };
    let out = args.get(2).map(PathBuf::from).unwrap_or_else(|| exe.clone());

    let data = fs::read(&exe).expect("read exe");
    let covered = data.len();
    let sk = SigningKey::try_from(self_sign_secret().as_slice()).expect("self-sign key");
    let vk = sk.verifying_key();
    let sig: Signature = sk.sign_raw(&data);

    let mut sigfile = Vec::with_capacity(SIG_FMT_LEN);
    sigfile.extend_from_slice(MAGIC);
    sigfile.extend_from_slice(&(covered as u64).to_le_bytes());
    sigfile.extend_from_slice(vk.to_bytes().as_ref());
    sigfile.extend_from_slice(sig.to_bytes().as_ref());
    assert_eq!(sigfile.len(), SIG_FMT_LEN, "signature block size");

    let mut final_data = data;
    final_data.extend_from_slice(&sigfile);
    fs::write(&out, &final_data).expect("write signed exe");
    println!(
        "signed {} -> {} (covered={} sigfile={})",
        exe.display(),
        out.display(),
        covered,
        SIG_FMT_LEN
    );
}
