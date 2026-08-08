#[path = "../shared.rs"]
mod shared;

mod crypto;
mod harden;
mod ntp;
mod pass;
mod rustyvm;
mod seccomp;
mod signal;
mod tui;
mod watchdog;

use std::io::{IsTerminal, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::fs::OpenOptions;

use rsa::{Oaep, RsaPrivateKey};
use rsa::pkcs8::DecodePrivateKey;
use ml_kem::{DecapsulationKey, MlKem1024};
use classic_mceliece_rust as mc;
use frodo_kem::{Algorithm as FrodoAlgorithm, DecryptionKey, Ciphertext};
use crystals_dilithium::ml_dsa_87::PublicKey;
use ed448_goldilocks::VerifyingKey;
use blake3;
use sha2::{Sha256, Digest};

mod siv_mod {
    include!("serpent_siv.rs");
}
use siv_mod::{siv_decrypt};

fn log_self_destruct(msg: &str) {
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("/home/admin/gitHub/hello_old/watchdog_debug.log") {
        let _ = writeln!(f, "{}", msg);
        let _ = f.flush();
    }
}

// Build-time embedded blobs for 7-layer runtime decryption
const PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.bin")); // legacy, unused now
const TS_BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ts.bin"));
const TS_PLAIN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ts_plain.bin"));
const VM_PROG_BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vmprog.bin"));
const KM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/km.bin"));
const SALT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/salt.bin"));

// Layer 2: RSA-4096-OAEP
const CT_RSA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ct_rsa.bin"));
const RSA_SK_WRAP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rsa_sk_wrap.bin"));

// Layer 3: Kyber-1024 (ML-KEM)
const CT_KY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ct_ky.bin"));
const KY_SK_WRAP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ky_sk_wrap.bin"));

// Layer 4: Classic McEliece-6960119f
const CT_MCE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ct_mce.bin"));
const MCE_SK_WRAP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/mce_sk_wrap.bin"));

// Layer 5: FrodoKEM-1344
const CT_FRODO: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ct_frodo.bin"));
const FRODO_SK_WRAP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/frodo_sk_wrap.bin"));

// Layer 6: CRYSTALS-Dilithium-5 (ML-DSA-87)
const DILITHIUM_SK_WRAP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dilithium_sk_wrap.bin"));
const DILITHIUM_VK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dilithium_vk.bin"));
const DILITHIUM_SIG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dilithium_sig.bin"));

// Layer 7: Serpent-256-SIV
const SIV_BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/serpent_siv.bin"));
const DEK_WRAP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dek_wrap.bin"));

// Layer 8: Ed448
const ED_VK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ed_vk.bin"));
const ED_SIG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ed_sig.bin"));

struct SecBuf {
    base: *mut u8,
    ptr: *mut u8,
    usable: usize,
    total: usize,
}

impl SecBuf {
    fn new(len: usize) -> Option<Self> {
        let page = 4096usize;
        let usable = if len <= page { page } else { (len + page - 1) & !(page - 1) };
        let total = usable + 2 * page;
        unsafe {
            let base = libc::mmap(
                std::ptr::null_mut(),
                total,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if base == libc::MAP_FAILED {
                return None;
            }
            let ptr = (base as *mut u8).add(page);
            if libc::mlock(ptr as *mut libc::c_void, usable) != 0 {
                libc::munmap(base as *mut libc::c_void, total);
                return None;
            }
            libc::mprotect(base as *mut libc::c_void, page, libc::PROT_NONE);
            libc::mprotect(ptr.add(usable) as *mut libc::c_void, page, libc::PROT_NONE);
            libc::madvise(ptr as *mut libc::c_void, usable, libc::MADV_DONTDUMP);
            Some(SecBuf { base: base as *mut u8, ptr, usable, total })
        }
    }

    fn lock_ro(&self) {
        unsafe {
            libc::mprotect(self.ptr as *mut libc::c_void, self.usable, libc::PROT_READ);
        }
    }

    fn lock_none(&self) {
        unsafe {
            libc::mprotect(self.ptr as *mut libc::c_void, self.usable, libc::PROT_NONE);
        }
    }
}

impl Drop for SecBuf {
    fn drop(&mut self) {
        unsafe {
            libc::mprotect(self.ptr as *mut libc::c_void, self.usable, libc::PROT_READ | libc::PROT_WRITE);
            let bytes = std::slice::from_raw_parts_mut(self.ptr, self.usable);
            for b in bytes.iter_mut() {
                std::ptr::write_volatile(b, 0);
            }
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            libc::munlock(self.ptr as *mut libc::c_void, self.usable);
            libc::munmap(self.base as *mut libc::c_void, self.total);
        }
    }
}

fn concat3(a: &[u8], b: &[u8], c: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(a.len() + b.len() + c.len());
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    v.extend_from_slice(c);
    v
}

fn xor5(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32], d: &[u8; 32], e: &[u8; 32]) -> [u8; 32] {
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = a[i] ^ b[i] ^ c[i] ^ d[i] ^ e[i];
    }
    o
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let zz = z + 719468;
    let era = (if zz >= 0 { zz } else { zz - 146096 }) / 146097;
    let doe = (zz - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn format_unix(ts: u64) -> String {
    let days = (ts / 86400) as i64;
    let sod = ts % 86400;
    let h = sod / 3600;
    let m = (sod % 3600) / 60;
    let s = sod % 60;
    let (y, mo, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", y, mo, d, h, m, s)
}

fn open_date_string() -> String {
    let days = (shared::OPEN_TIMESTAMP_UNIX_SECONDS / 86400) as i64;
    let (y, mo, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}", y, mo, d)
}

fn refuse(lines: &[String], feed: &dyn Fn()) -> ! {
    let unlock_time = format_unix(shared::OPEN_TIMESTAMP_UNIX_SECONDS);
    tui::show(lines, feed, &unlock_time);
    let width = tui::term_width();
    let height = tui::term_height();
    tui::burn_with_progress(width, height, feed);
    watchdog::stop();
    std::process::exit(1);
}

fn consensus(results: &[(String, f64, f64)]) -> Option<(f64, f64)> {
    let mut good: Vec<(f64, f64)> = results
        .iter()
        .filter(|(_, _, d)| d.abs() < shared::CLOCK_DRIFT_LIMIT_SECONDS)
        .map(|(_, n, d)| (*n, *d))
        .collect();
    if good.is_empty() {
        return None;
    }
    good.sort_by(|a, b| a.1.abs().partial_cmp(&b.1.abs()).unwrap_or(std::cmp::Ordering::Equal));
    Some(good[good.len() / 2])
}

fn key_copy64(buf: &SecBuf) -> [u8; 64] {
    let mut k = [0u8; 64];
    unsafe {
        std::ptr::copy_nonoverlapping(buf.ptr, k.as_mut_ptr(), 64);
    }
    k
}

fn noop() {}

fn anti_debug_checks() -> bool {
    if watchdog::tracer_pid() != 0 {
        return false;
    }
    unsafe {
        if libc::prctl(libc::PR_SET_PTRACER, 0, 0, 0, 0) == -1 {
        }
    }
    
    let start = Instant::now();
    std::hint::black_box(0);
    let elapsed = start.elapsed();
    if elapsed > Duration::from_millis(5) {
        return false;
    }
    
    true
}

fn hacker_ntp_report(results: &[(String, f64, f64)]) -> Vec<String> {
    let mut report: Vec<String> = Vec::new();
    let width = tui::term_width();
    let sep: String = std::iter::repeat('═').take(width).collect();

    report.push(sep.clone());
    report.push("  █ NTP CONSENSUS SCAN █".to_string());
    report.push(sep.clone());
    report.push(String::new());

    for (host, _n, d) in results {
        let status = if d.abs() < shared::CLOCK_DRIFT_LIMIT_SECONDS {
            format!("{}{}✓ VALID{}  drift {:+.3}s", C_GREEN, C_BRIGHT_WHITE, C_RESET, d)
        } else {
            format!("{}{}✗ REJECTED{}  drift {:+.3}s", C_RED, C_BRIGHT_WHITE, C_RESET, d)
        };
        report.push(format!("  [{:<24}] {}", host, status));
    }

    report.push(String::new());
    report
}

fn success_sequence(feed: &dyn Fn()) {
    let width = tui::term_width();
    let height = tui::term_height();
    let mut rng = tui::Rng::new();

    tui::clear();
    
    let msgs = [
        "█ ACCESS GRANTED █",
        "█ DECRYPTION SUCCESSFUL █",
        "█ PAYLOAD READY █",
    ];
    
    for msg in msgs {
        tui::dynamic_center_message(msg, C_GREEN, feed);
        tui::sleep(50);
    }
    
    tui::clear();
    
    for _ in 0..12 {
        for r in 1..=height {
            let g = rng.fill_line(width);
            tui::cursor(r, 1);
            print!("{}{}{}", C_GREEN, g, C_RESET);
        }
        tui::flush();
        tui::sleep(50);
        feed();
    }
    
    tui::clear();
}

fn main() {
    if !anti_debug_checks() {
        std::process::exit(137);
    }

    signal::ignore();
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        libc::prctl(0x59616d61, 0, 0, 0, 0);
    }

    if !harden::check_injection() {
        refuse(
            &["INJECTION DETECTED".to_string(), "Access denied".to_string()],
            &noop,
        );
    }

    let key_buf = match SecBuf::new(64) {
        Some(b) => b,
        None => refuse(
            &["Memory lock failed".to_string(), "Access denied".to_string()],
            &noop,
        ),
    };
    let content_buf = match SecBuf::new(PAYLOAD.len()) {
        Some(b) => b,
        None => refuse(
            &["Memory lock failed".to_string(), "Access denied".to_string()],
            &noop,
        ),
    };

    tui::hide_cursor();
    tui::clear();
    let width = tui::term_width();
    let height = tui::term_height();

    let open_date = open_date_string();
    let date_label = format!("Door opens on {}", open_date);
    tui::dynamic_center_message(&date_label, C_YELLOW, &noop);

    let prompt = "Enter decryption password:";
    let mut prog: Vec<u8>;
    loop {
        tui::dynamic_center_prompt(prompt, &noop);
        let mut password = match pass::read_password() {
            Some(p) if !p.is_empty() => p,
            _ => {
                if !std::io::stdin().is_terminal() {
                    watchdog::self_destruct();
                }
                tui::dynamic_center_error("Invalid password, try again", &noop);
                continue;
            }
        };

        let mut master_key = crypto::argon2id_hash(&password, SALT);
        zeroize(password.as_mut_slice());

        let mut boot = concat3(&master_key, b"bootstrap", b"");
        let mut bk = crypto::sha3_256(&boot);
        zeroize(&mut boot);
        zeroize(&mut master_key);

        match crypto::decrypt(&bk, VM_PROG_BLOB) {
            Some(p) => {
                zeroize(&mut bk);
                prog = p;
                break;
            }
            None => {
                zeroize(&mut bk);
                if !std::io::stdin().is_terminal() {
                    watchdog::self_destruct();
                }
                tui::dynamic_center_error("Invalid password, try again", &noop);
            }
        }
    }
    let mut keys = [0u8; shared::KEY_LEN];

    const DECRYPT_STAGES: [&str; 6] = [
        "Verifying key derivation",
        "Executing VM bootstrap",
        "Hardening memory & watchdog",
        "Querying NTP servers",
        "Computing time consensus",
        "Releasing payload",
    ];
    let mut fx = tui::DecryptFx::new(width, height, &DECRYPT_STAGES);

    for i in 0..6 {
        fx.draw(i as f32 / 5.0, &noop);
        tui::sleep(50);
    }
    fx.advance();

    fx.draw(0.0, &noop);
    if !rustyvm::run(&prog, KM, &mut keys) {
        log_self_destruct("main: rustyvm run failed");
        watchdog::self_destruct();
    }
    zeroize(prog.as_mut_slice());
    unsafe {
        std::ptr::copy_nonoverlapping(keys.as_ptr(), key_buf.ptr, shared::KEY_LEN);
    }
    zeroize(&mut keys);
    for i in 0..5 {
        fx.draw(0.3 + i as f32 * 0.14, &noop);
        tui::sleep(50);
    }
    fx.advance();

    let key_sha = crypto::sha3_256(&key_copy64(&key_buf));
    log_self_destruct(&format!("main: key_sha={:?}", key_sha));
    let feed: Arc<Mutex<Instant>> = watchdog::start(key_sha, key_buf.ptr as usize, 64);
    key_buf.lock_ro();
    let beat = || {
        *feed.lock().unwrap() = Instant::now();
    };
    beat();
    fx.draw(0.25, &beat);

    let anchor = harden::ClockAnchor::new();
    if !anchor.sane() {
        refuse(
            &["Clock jump detected".to_string(), "Access denied".to_string()],
            &beat,
        );
    }
    fx.draw(0.5, &beat);

    if !seccomp::install() {
        refuse(
            &["seccomp install failed".to_string(), "Access denied".to_string()],
            &beat,
        );
    }
    fx.draw(0.7, &beat);

    let local_now = ntp::unix_now_u64();
    let (local_year, _, _) = civil_from_days((local_now / 86400) as i64);
    if !(2020..=2100).contains(&local_year) {
        refuse(
            &["Local clock suspicious".to_string(), "Access denied".to_string()],
            &beat,
        );
    }
    for i in 0..3 {
        fx.draw(0.8 + i as f32 * 0.07, &beat);
        tui::sleep(50);
    }
    fx.advance();

    fx.draw(0.0, &beat);
    let mut report: Vec<String> = Vec::new();
    report.push(format!("Local time    {}", format_unix(local_now)));

    let results = ntp::sync_all(&shared::NTP_SERVERS, &mut |done, total| {
        let a = if total > 0 { done as f32 / total as f32 } else { 1.0 };
        fx.draw(a, &beat);
    });
    fx.advance();

    fx.draw(0.0, &beat);
    let (ntp_now, ntp_drift) = match consensus(&results) {
        Some((n, d)) => (n, d),
        None => {
            let custom_prompt = "All NTP servers unreachable. Enter custom NTP host:";
            let cpad = tui::center_pad(custom_prompt, width);
            tui::cursor(height / 2, cpad + 1);
            print!("{}{}{}", C_CYAN, custom_prompt, C_RESET);
            tui::flush();
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            let host = line.trim().to_string();
            match ntp::query(&host) {
                Some((n, d)) if d.abs() < shared::CLOCK_DRIFT_LIMIT_SECONDS => (n, d),
                Some((_, d)) => {
                    refuse(
                        &[(format!("Custom NTP drift {:.1}s", d)), "Access denied".to_string()],
                        &beat,
                    );
                }
                None => refuse(
                    &["Custom NTP verification failed".to_string(), "Access denied".to_string()],
                    &beat,
                ),
            }
        }
    };
    for i in 0..4 {
        fx.draw(0.5 + i as f32 * 0.12, &beat);
        tui::sleep(50);
    }
    fx.advance();

    if !anchor.sane() {
        refuse(
            &["Clock jump detected".to_string(), "Access denied".to_string()],
            &beat,
        );
    }

    report.push(format!("NTP time     {}", format_unix(ntp_now.floor() as u64)));
    report.push(format!("Clock drift  {:.3}s", ntp_drift));
    report.push(format!(
        "Hardening    seccomp {} rules · injection check · guard pages · anti-debug",
        seccomp::rule_count()
    ));

    let hacker_lines = hacker_ntp_report(&results);
    for line in hacker_lines {
        report.push(line);
    }
    report.push(String::new());

    fx.draw(0.0, &beat);
    beat();
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    {
        let mut all = key_copy64(&key_buf);
        log_self_destruct(&format!("main: all key={:?}", all));
        k1.copy_from_slice(&all[..32]);
        k2.copy_from_slice(&all[32..]);
        log_self_destruct(&format!("main: k1={:?}, k2={:?}", k1, k2));
        zeroize(&mut all);
    }

    let open_ts = {
        let mut blob = match crypto::decrypt(&k1, TS_BLOB) {
            Some(b) => b,
            None => { log_self_destruct("main: decrypt TS_BLOB failed"); watchdog::self_destruct(); }
        };
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&blob[..8]);
        let ts = u64::from_le_bytes(arr);
        crypto::zeroize(blob.as_mut_slice());
        if !crypto::ct_eq(&ts.to_le_bytes(), &shared::OPEN_TIMESTAMP_UNIX_SECONDS.to_le_bytes()) {
            log_self_destruct("main: timestamp mismatch");
            watchdog::self_destruct();
        }
        ts
    };

    {
        let plain_ts = u64::from_le_bytes([
            TS_PLAIN[0], TS_PLAIN[1], TS_PLAIN[2], TS_PLAIN[3],
            TS_PLAIN[4], TS_PLAIN[5], TS_PLAIN[6], TS_PLAIN[7],
        ]);
        if plain_ts != shared::OPEN_TIMESTAMP_UNIX_SECONDS || plain_ts != open_ts {
            log_self_destruct("main: plain timestamp mismatch");
            watchdog::self_destruct();
        }
    }

    let now_u64 = ntp_now.floor() as u64;
    if now_u64 < open_ts {
        let mut lines = report.clone();
        lines.push("DOOR IS LOCKED".to_string());
        lines.push(format!("Opens at     {}", format_unix(open_ts)));
        lines.push(format!("Time left    {} seconds", open_ts - now_u64));
        lines.push("Time has not yet arrived".to_string());
        refuse(&lines, &beat);
    }
    for i in 0..4 {
        fx.draw(0.55 + i as f32 * 0.1, &beat);
        tui::sleep(50);
    }

    beat();

    // ============================================================
    // 7-LAYER POST-QUANTUM TIME-GATED DECRYPTION
    // ============================================================
    fx.draw(0.0, &beat);
    
    // Derive 6 independent wrapping keys from master key (k1||k2)
    let mut wrapping_keys = crypto::derive_wrapping_keys(&k1);
    let mut rsa_wrap_key = wrapping_keys[0];
    let mut kyber_wrap_key = wrapping_keys[1];
    let mut mceliece_wrap_key = wrapping_keys[2];
    let mut frodokem_wrap_key = wrapping_keys[3];
    let mut dilithium_wrap_key = wrapping_keys[4];
    let mut serpent_dek_wrap_key = wrapping_keys[5];
    for k in wrapping_keys.iter_mut() {
        crypto::zeroize(k);
    }

    // Layer 2: RSA-4096-OAEP
    fx.draw(0.1, &beat);
    let mut rsa_sk_der = match crypto::decrypt(&rsa_wrap_key, RSA_SK_WRAP) {
        Some(b) => b,
        None => { log_self_destruct("main: unwrap RSA SK failed"); watchdog::self_destruct(); }
    };
    let rsa_sk = RsaPrivateKey::from_pkcs8_der(&rsa_sk_der).expect("RSA PKCS8 parse");
    let oaep = Oaep::new_with_mgf_hash::<Sha256, Sha256>();
    let s_rsa = rsa_sk.decrypt(oaep, CT_RSA).expect("RSA OAEP decrypt");
    let mut s_rsa_arr = [0u8; 32];
    s_rsa_arr.copy_from_slice(&s_rsa[..32]);
    crypto::zeroize(rsa_sk_der.as_mut_slice());
    crypto::zeroize(&mut rsa_wrap_key);

    // Layer 3: Kyber-1024
    fx.draw(0.2, &beat);
    let mut ky_sk_bytes = match crypto::decrypt(&kyber_wrap_key, KY_SK_WRAP) {
        Some(b) => b,
        None => { log_self_destruct("main: unwrap Kyber SK failed"); watchdog::self_destruct(); }
    };
    let dk_ky = {
        let seed_bytes: [u8; 64] = ky_sk_bytes[..64].try_into().expect("kyber seed len");
        let seed = ml_kem::Seed::from(seed_bytes);
        DecapsulationKey::<MlKem1024>::from_seed(seed)
    };
    let sh_ky = {
        use ml_kem::Decapsulate;
        let ct = ml_kem::Ciphertext::<MlKem1024>::try_from(CT_KY).expect("kyber ct len");
        dk_ky.decapsulate(&ct)
    };
    let mut s_ky_arr = [0u8; 32];
    s_ky_arr.copy_from_slice(sh_ky.as_slice());
    crypto::zeroize(ky_sk_bytes.as_mut_slice());
    crypto::zeroize(&mut kyber_wrap_key);

    // Layer 4: Classic McEliece-6960119f
    fx.draw(0.3, &beat);
    let mut mce_sk_bytes = match crypto::decrypt(&mceliece_wrap_key, MCE_SK_WRAP) {
        Some(b) => b,
        None => { log_self_destruct("main: unwrap McEliece SK failed"); watchdog::self_destruct(); }
    };
    let mut mce_sk_arr: [u8; mc::CRYPTO_SECRETKEYBYTES] = mce_sk_bytes.as_slice().try_into().expect("mceliece sk len");
    let sk_mce = mc::SecretKey::from(&mut mce_sk_arr);
    let ct_mce_arr: [u8; mc::CRYPTO_CIPHERTEXTBYTES] = {
        let mut arr = [0u8; mc::CRYPTO_CIPHERTEXTBYTES];
        arr.copy_from_slice(&CT_MCE[..mc::CRYPTO_CIPHERTEXTBYTES]);
        arr
    };
    let sh_mce = mc::decapsulate_boxed(&mc::Ciphertext::from(ct_mce_arr), &sk_mce);
    let mut s_mce_arr = [0u8; 32];
    s_mce_arr.copy_from_slice(&sh_mce.as_array()[..32]);
    crypto::zeroize(mce_sk_bytes.as_mut_slice());
    crypto::zeroize(&mut mceliece_wrap_key);

    // Layer 5: FrodoKEM-1344
    fx.draw(0.4, &beat);
    let mut frodo_sk_bytes = match crypto::decrypt(&frodokem_wrap_key, FRODO_SK_WRAP) {
        Some(b) => b,
        None => { log_self_destruct("main: unwrap FrodoKEM SK failed"); watchdog::self_destruct(); }
    };
    let frodo_alg = FrodoAlgorithm::FrodoKem1344Aes;
    let frodo_sk = DecryptionKey::from_bytes(frodo_alg, &frodo_sk_bytes).expect("FrodoKEM SK parse");
    let frodo_ct = Ciphertext::from_bytes(frodo_alg, &CT_FRODO).expect("FrodoKEM ciphertext parse");
    let (_sh_frodo, frodo_msg) = frodo_alg.decapsulate(&frodo_sk, &frodo_ct).expect("FrodoKEM decap");
    let mut s_frodo_arr = [0u8; 32];
    s_frodo_arr.copy_from_slice(&frodo_msg[..32]);
    crypto::zeroize(frodo_sk_bytes.as_mut_slice());
    crypto::zeroize(&mut frodokem_wrap_key);

    // Layer 6: CRYSTALS-Dilithium-5 (ML-DSA-87) - verify signature
    fx.draw(0.5, &beat);
    let dilithium_vk_bytes = DILITHIUM_VK;
    let dilithium_sig_bytes = DILITHIUM_SIG;
    let dilithium_vk = PublicKey::from_bytes(dilithium_vk_bytes).expect("Dilithium VK parse");
    // Verify Dilithium signature over (ts|dek|sha256(siv)) - will do after DEK recovery
    crypto::zeroize(&mut dilithium_wrap_key);

    // Layer 7: Serpent-256-SIV - recover DEK and decrypt
    fx.draw(0.6, &beat);
    let mut dek_wrapped = match crypto::decrypt(&serpent_dek_wrap_key, DEK_WRAP) {
        Some(b) => b,
        None => { log_self_destruct("main: unwrap DEK failed"); watchdog::self_destruct(); }
    };
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_wrapped[..32]);
    crypto::zeroize(dek_wrapped.as_mut_slice());
    crypto::zeroize(&mut serpent_dek_wrap_key);

    // Combine shards: RSA ^ Kyber ^ McEliece ^ FrodoKEM ^ Dilithium
    // Note: Dilithium shard is blake3 hash of public key
    let dilithium_pk_hash_bytes: [u8; 32] = *blake3::hash(dilithium_vk_bytes).as_bytes();
    let mut s_dilithium_arr = [0u8; 32];
    s_dilithium_arr.copy_from_slice(&dilithium_pk_hash_bytes);
    
    let mut combined_dek = xor5(&s_rsa_arr, &s_ky_arr, &s_mce_arr, &s_frodo_arr, &s_dilithium_arr);
    
    // Constant-time compare DEK
    if !crypto::ct_eq(&combined_dek, &dek) {
        log_self_destruct("main: DEK mismatch");
        watchdog::self_destruct();
    }
    crypto::zeroize(&mut s_rsa_arr);
    crypto::zeroize(&mut s_ky_arr);
    crypto::zeroize(&mut s_mce_arr);
    crypto::zeroize(&mut s_frodo_arr);
    crypto::zeroize(&mut s_dilithium_arr);
    crypto::zeroize(&mut dek);

    // Verify Dilithium signature over (ts|dek|sha256(siv))
    fx.draw(0.7, &beat);
    let mut verify_msg = Vec::with_capacity(8 + 32 + 32);
    verify_msg.extend_from_slice(&open_ts.to_le_bytes());
    verify_msg.extend_from_slice(&combined_dek);
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(SIV_BLOB);
    let siv_hash = sha256_hasher.finalize();
    verify_msg.extend_from_slice(&siv_hash);
    
    if !dilithium_vk.verify(&verify_msg, dilithium_sig_bytes, None) {
        log_self_destruct("main: Dilithium signature verification failed");
        watchdog::self_destruct();
    }

    // Layer 8: Ed448 - verify signature
    fx.draw(0.8, &beat);
    let ed_vk = VerifyingKey::from_bytes(&ED_VK.try_into().expect("Ed448 VK len")).expect("Ed448 VK parse");
    let ed_sig = ed448_goldilocks::Signature::from_bytes(&ED_SIG.try_into().expect("Ed448 sig len"));
    if ed_vk.verify_raw(&ed_sig, &verify_msg).is_err() {
        log_self_destruct("main: Ed448 signature verification failed");
        watchdog::self_destruct();
    }

    // Decrypt Serpent-256-SIV payload
    fx.draw(0.9, &beat);
    let mut content = siv_decrypt(&combined_dek, &open_ts.to_le_bytes(), SIV_BLOB)
        .expect("SIV decrypt failed");
    crypto::zeroize(&mut combined_dek);

    // Copy content into secure buffer
    beat();
    unsafe {
        std::ptr::copy_nonoverlapping(content.as_ptr(), content_buf.ptr, content.len());
    }

    fx.finish(&beat);

    // Success sequence and display
    success_sequence(&beat);

    let text = unsafe { std::slice::from_raw_parts(content_buf.ptr, content.len()) };
    let text = String::from_utf8_lossy(text).into_owned();
    let mut all = report;
    for line in text.lines() {
        all.push(line.to_string());
    }

    beat();
    let unlock_time = format_unix(open_ts);
    let rows0 = tui::show(&all, &beat, &unlock_time);
    let width = tui::term_width();

    let hint = "Press q to burn and exit";
    let hr = rows0 + 1;
    let hpad = tui::center_pad(hint, width);
    tui::hide_cursor();
    print!(
        "\x1b[{};{}H{}{}{}{}{}",
        hr, 1,
        C_BG_DARK, "\x1b[2m",
        format!("{}{}", " ".repeat(hpad), hint),
        " ".repeat(width.saturating_sub(hpad + hint.len())),
        C_RESET
    );
    flush_stdout();
    tui::wait_for_quit(&beat);

    watchdog::stop();
    let height = tui::term_height();
    tui::burn_with_progress(width, height, &beat);
    key_buf.lock_none();
    content_buf.lock_none();

    // Zeroize content before exit
    crypto::zeroize(content.as_mut_slice());

    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(exe);
    }
}

fn zeroize(buf: &mut [u8]) {
    crypto::zeroize(buf);
}

fn flush_stdout() {
    let _ = std::io::stdout().flush();
}

use tui::{C_RESET, C_CYAN, C_GREEN, C_RED, C_YELLOW, C_BRIGHT_WHITE, C_BG_DARK};