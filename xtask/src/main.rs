use std::fs;
use std::path::PathBuf;

use ed448_goldilocks::{Signature, SigningKey};

const MAGIC: &[u8; 8] = b"HLDLSIG1";
const SIG_FMT_LEN: usize = 8 + 8 + 57 + 114;

/// Master signing secret (32 bytes), identical to build.rs: read from the
/// HELLO_OLD_SELF_SIGN_KEY env var (64 hex chars) or the git-ignored file
/// <repo>/signing/selfsign.key, so the overlay signature matches the verifying
/// key embedded in the binary at build time. Refuses to sign without it.
fn self_sign_secret() -> [u8; 57] {
    let mut seed = [0u8; 32];
    let loaded = if let Ok(hex) = std::env::var("HELLO_OLD_SELF_SIGN_KEY") {
        seed = decode_hex32(hex.trim())
            .unwrap_or_else(|e| panic!("HELLO_OLD_SELF_SIGN_KEY invalid: {e}"));
        true
    } else {
        let root = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
        let path = std::path::Path::new(&root).join("..").join("signing").join("selfsign.key");
        if let Ok(hex) = std::fs::read_to_string(&path) {
            seed = decode_hex32(hex.trim())
                .unwrap_or_else(|e| panic!("{} invalid: {e}", path.display()));
            true
        } else {
            false
        }
    };
    if !loaded {
        eprintln!(
            "refusing to sign: no self-signing secret. Set HELLO_OLD_SELF_SIGN_KEY \
             (64 hex chars) or provide signing/selfsign.key (git-ignored)."
        );
        std::process::exit(2);
    }
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
