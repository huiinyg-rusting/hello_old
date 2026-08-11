#[path = "../shared.rs"]
mod shared;

mod crypto;
mod harden;
mod ntp;
mod pass;
mod rolling;
mod rustyvm;
mod seccomp;
mod signal;
mod tui;
mod watchdog;

use std::io::IsTerminal;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

// Build-time embedded blobs for 7-layer runtime decryption
const PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.bin")); // legacy, unused now
const TS_BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ts.bin"));
const TS_GUARD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ts_guard.bin"));
const VM_PROG_BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vmprog.bin"));
const VM_PROG_HASH: &[u8; 32] = include_bytes!(concat!(env!("OUT_DIR"), "/vmprog_hash.bin"));
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
const DILITHIUM_VK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dilithium_vk.bin"));
const DILITHIUM_SIG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dilithium_sig.bin"));

// Layer 7: Serpent-256-SIV
const SIV_BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/serpent_siv.bin"));
const DEK_WRAP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dek_wrap.bin"));

// Layer 8: Ed448
const ED_VK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ed_vk.bin"));
const ED_SIG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ed_sig.bin"));

#[cfg(target_os = "linux")]
struct SecBuf {
    base: *mut u8,
    ptr: *mut u8,
    usable: usize,
    total: usize,
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

// Windows: VirtualAlloc guard pages + VirtualLock + VirtualProtect, mirroring
// the Linux mmap/mlock/mprotect layout (guard pages before/after the payload).
#[cfg(target_os = "windows")]
struct SecBuf {
    base: *mut u8,
    ptr: *mut u8,
    usable: usize,
    #[allow(dead_code)]
    total: usize,
}

#[cfg(target_os = "windows")]
impl SecBuf {
    fn new(len: usize) -> Option<Self> {
        use windows_sys::Win32::System::Memory::{
            VirtualAlloc, VirtualFree, VirtualLock, VirtualProtect, MEM_COMMIT, MEM_RESERVE,
            PAGE_NOACCESS, PAGE_READWRITE,
        };
        const PAGE: usize = 4096;
        let usable = if len <= PAGE { PAGE } else { (len + PAGE - 1) & !(PAGE - 1) };
        let total = usable + 2 * PAGE;
        unsafe {
            let base = VirtualAlloc(
                std::ptr::null(),
                total,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            );
            if base.is_null() {
                return None;
            }
            let ptr = (base as *mut u8).add(PAGE);
            let mut old: u32 = 0;
            if VirtualLock(ptr as *const _, usable) == 0 {
                VirtualFree(base, 0, 0x8000); // MEM_RELEASE
                return None;
            }
            VirtualProtect(base as *const _, PAGE, PAGE_NOACCESS, &mut old);
            VirtualProtect(ptr.add(usable) as *const _, PAGE, PAGE_NOACCESS, &mut old);
            Some(SecBuf { base: base as *mut u8, ptr, usable, total })
        }
    }

    fn lock_ro(&self) {
        use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_READONLY};
        unsafe {
            let mut old: u32 = 0;
            VirtualProtect(self.ptr as *const _, self.usable, PAGE_READONLY, &mut old);
        }
    }

    fn lock_none(&self) {
        use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_NOACCESS};
        unsafe {
            let mut old: u32 = 0;
            VirtualProtect(self.ptr as *const _, self.usable, PAGE_NOACCESS, &mut old);
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for SecBuf {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Memory::{
            VirtualFree, VirtualProtect, VirtualUnlock, PAGE_READWRITE,
        };
        unsafe {
            let mut old: u32 = 0;
            VirtualProtect(self.ptr as *const _, self.usable, PAGE_READWRITE, &mut old);
            let bytes = std::slice::from_raw_parts_mut(self.ptr, self.usable);
            for b in bytes.iter_mut() {
                std::ptr::write_volatile(b, 0);
            }
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            VirtualUnlock(self.ptr as *const _, self.usable);
            VirtualFree(self.base as *mut _, 0, 0x8000); // MEM_RELEASE
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

fn xor6(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32], d: &[u8; 32], e: &[u8; 32], f: &[u8; 32]) -> [u8; 32] {
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = a[i] ^ b[i] ^ c[i] ^ d[i] ^ e[i] ^ f[i];
    }
    o
}

/// The real open timestamp is only ever referenced through an XOR mask so the
/// plain value (2_755_000_000 / its LE bytes) never appears as an immediate
/// constant in the binary. The mask is a fixed compile-time value, so this is
/// anti-`strings`/anti-location hardening, not secrecy — matching the M4/M5
/// obfuscation tier for the time-gate anchor.
const TS_MASK: u64 = 0xA5A5_5A5A_0FF0_F00F;
const OPEN_TS_ENC: u64 = shared::OPEN_TIMESTAMP_UNIX_SECONDS ^ TS_MASK;

/// `black_box` keeps the mask opaque to the optimizer so `OPEN_TS_ENC ^ mask`
/// is NOT constant-folded back into the plain (2_755_000_000) as an immediate;
/// only the two masked halves ever appear in the binary. The function is not
/// inlined so the fold cannot happen at a call site either.
#[inline(never)]
fn open_ts_ref() -> u64 {
    let m = std::hint::black_box(TS_MASK);
    OPEN_TS_ENC ^ m
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
    let days = (open_ts_ref() / 86400) as i64;
    let (y, mo, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}", y, mo, d)
}

/// Constant-equivalent check: `now >= open_ts`. Written as a few arithmetic
/// rewrites that are algebraically equivalent to the plain comparison but do
/// not appear as a bare `now < open_ts` in the binary, so a static patch is
/// harder to target. No secret-indexed access and no secret-dependent branch.
///
/// The opaque predicates below are algebraically always-true/false idioms
/// (M4). Each reduces to the identity, so they never change the result, but
/// they bury the real gate under arithmetic that a toolchain / analyst must
/// evaluate to notice it is dead code.
fn time_gate_open(now: u64, open_ts: u64) -> bool {
    // now >= open_ts  <=>  (now - open_ts) does not wrap to a huge value
    // i.e. now.wrapping_sub(open_ts) as i64 is >= 0.
    let gate = (now.wrapping_sub(open_ts) as i64) >= 0;

    // M4 opaque predicates: always-true / always-false arithmetic idioms.
    // x^2 - 6x + 9 == (x-3)^2 >= 0; evaluating on a stolen constant yields 0
    // either way so the following branch is provably dead but not obviously.
    let x = (now.wrapping_sub(now) & 0xffff) as u64; // 0
    let always_zero = x.wrapping_mul(x).wrapping_sub(6u64.wrapping_mul(x)).wrapping_add(9); // 9
    let dead_branch = always_zero == 0; // false
    if dead_branch {
        return !gate;
    }
    gate
}

/// Parse the embedded metadata JSON `{"created":..,"modified":..,"author":".."}`
/// into human-readable display lines.
fn parse_meta(meta: &[u8]) -> Vec<String> {
    let s = String::from_utf8_lossy(meta);
    let s = s.trim().trim_start_matches('{').trim_end_matches('}');
    let mut created = None;
    let mut modified = None;
    let mut author = String::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("\"created\":") {
            created = v.trim().parse::<u64>().ok();
        } else if let Some(v) = part.strip_prefix("\"modified\":") {
            modified = v.trim().parse::<u64>().ok();
        } else if let Some(v) = part.strip_prefix("\"author\":\"") {
            author = v.trim_end_matches('"').trim().to_string();
        }
    }
    let mut lines = Vec::new();
    lines.push("── 档案信息 · SEALED RECORD ──".to_string());
    if let Some(c) = created {
        lines.push(format!("创建 / Created   {}", format_unix(c)));
    }
    if let Some(m) = modified {
        lines.push(format!("修改 / Modified  {}", format_unix(m)));
    }
    if !author.is_empty() {
        lines.push(format!("作者 / Author    {}", author));
    }
    lines
}

fn refuse(lines: &[String], feed: &dyn Fn()) -> ! {
    let unlock_time = format_unix(open_ts_ref());
    tui::show(lines, feed, &unlock_time, false);
    watchdog::stop();
    tui::show_cursor();
    std::process::exit(1);
}

/// Verify the timestamp integrity guard. The guard stores 8 XOR-masked
/// fragments, 8 random masks, a random 8-byte recomposition order and a
/// SHA3-256 chain over (frag, mask) pairs walked in that order. All pieces are
/// embedded independently; to forge a new open time an attacker would have to
/// rewrite every fragment, every mask, the order and the chain consistently —
/// a single stray byte makes the recomposed value fail the hash check.
fn ts_guard_valid(ts: u64) -> bool {
    if TS_GUARD.len() != 8 * 8 + 8 * 8 + 8 + 32 {
        return false;
    }
    let mut frags = [0u64; 8];
    let mut masks = [0u64; 8];
    let mut order = [0u8; 8];
    for i in 0..8 {
        let mut f = [0u8; 8];
        f.copy_from_slice(&TS_GUARD[i * 8..i * 8 + 8]);
        frags[i] = u64::from_le_bytes(f);
    }
    for i in 0..8 {
        let mut m = [0u8; 8];
        m.copy_from_slice(&TS_GUARD[64 + i * 8..64 + i * 8 + 8]);
        masks[i] = u64::from_le_bytes(m);
    }
    order.copy_from_slice(&TS_GUARD[128..136]);
    let expected_chain = &TS_GUARD[136..];

    // Recover the open time from every fragment; all must agree.
    for i in 0..8 {
        if frags[i] ^ masks[i] != ts {
            return false;
        }
    }

    let mut chain_input = Vec::with_capacity(128);
    for i in 0..8 {
        let idx = (order[i] as usize) % 8;
        chain_input.extend_from_slice(&frags[idx].to_le_bytes());
        chain_input.extend_from_slice(&masks[idx].to_le_bytes());
    }
    crypto::ct_eq(&crypto::sha3_256(&chain_input), expected_chain)
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

/// Side-channel hardening: burn a fixed, secret-independent amount of work
/// so a wrong password takes ~as long as a full derivation before revealing
/// the outcome, and evict the derived secret buffers from cache.
fn timing_equalize() {
    crypto::burn_cycles(8_000_000);
    let mut scratch = [0u8; 128];
    for chunk in scratch.chunks_mut(16) {
        let mut acc = 0x243f_6a88_85a3_08d3u64;
        for b in chunk.iter_mut() {
            acc = acc.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (acc >> 56) as u8;
        }
    }
    crypto::flush_mem(scratch.as_ptr(), scratch.len());
    crypto::zeroize(&mut scratch);
}

/// Random micro-delay (0..8ms) applied to both success and failure paths so
/// any residual timing difference that a jitter-free equalizer missed is
/// buried in noise. Uses OS entropy so the delay is not predictable.
fn timing_jitter() {
    use std::time::Duration;
    let mut b = [0u8; 2];
    if getrandom::getrandom(&mut b).is_ok() {
        let ms = u16::from_le_bytes(b) % 9;
        std::thread::sleep(Duration::from_millis(ms as u64));
    }
}

/// Resolve an ntdll export address without GetProcAddress so a hooked
/// GetProcAddress cannot hide the function. We walk the PE export table of
/// the mapped ntdll module directly.
#[cfg(target_os = "windows")]
fn get_ntdll_proc(name: &str) -> Option<*const std::ffi::c_void> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    unsafe {
        let wide: Vec<u16> = std::ffi::OsStr::new("ntdll.dll")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let m = GetModuleHandleW(wide.as_ptr());
        if m.is_null() {
            return None;
        }
        let base = m as usize;
        let pe_off = *((base as *const u8).add(0x3c) as *const u32);
        let pe = (base + pe_off as usize) as *const u8;
        // IMAGE_NT_HEADERS: Signature(4) + FileHeader(20) + OptionalHeader.
        // Export dir is DataDirectory[0] of the PE32+ optional header, which
        // begins at optional header offset 0x70 (RVA + Size, two u32s).
        let exp_rva_off = 4 + 20 + 0x70;
        let export_rva = *((pe.add(exp_rva_off)) as *const u32);
        let export_size = *((pe.add(exp_rva_off + 4)) as *const u32);
        if export_rva == 0 || export_rva as usize + export_size as usize > 0x1000_0000 {
            return None;
        }
        let exp = (base + export_rva as usize) as *const u8;
        let names_cnt = *((exp.add(0x18)) as *const u32) as usize;
        let funcs_rva = *((exp.add(0x1c)) as *const u32) as usize;
        let names_rva = *((exp.add(0x20)) as *const u32) as usize;
        let ords_rva = *((exp.add(0x24)) as *const u32) as usize;
        let names_arr = (base + names_rva) as *const u32;
        let funcs_arr = (base + funcs_rva) as *const u32;
        let ords_arr = (base + ords_rva) as *const u16;
        for i in 0..names_cnt {
            let name_rva = *names_arr.add(i) as usize;
            let n = (base + name_rva) as *const u8;
            let mut k = 0usize;
            while *n.add(k) != 0 && k < 128 {
                k += 1;
            }
            let s = std::slice::from_raw_parts(n, k);
            if s == name.as_bytes() {
                let ord = *ords_arr.add(i) as usize;
                let f = *funcs_arr.add(ord);
                return Some((base + f as usize) as *const std::ffi::c_void);
            }
        }
        None
    }
}

/// Enumerate visible top-level windows and flag common GUI debuggers by
/// title substring. Cheap and very noisy to false-positive on, so only the
/// most distinctive known titles are matched.
/// M5: debugger window titles stored as XOR-masked byte slices; unmasked at
/// runtime so the match list is not present as plaintext strings in the binary.
#[cfg(target_os = "windows")]
fn xor_patterns() -> Vec<String> {
    const X: u8 = 0x0d;
    // (title ^ X) for each known debugger window-title substring.
    const RAW: &[&[u8]] = &[
        &[b'x' ^ X, b'6' ^ X, b'4' ^ X, b'd' ^ X, b'b' ^ X, b'g' ^ X],
        &[b'x' ^ X, b'3' ^ X, b'2' ^ X, b'd' ^ X, b'b' ^ X, b'g' ^ X],
        &[b'O' ^ X, b'l' ^ X, b'l' ^ X, b'y' ^ X, b'D' ^ X, b'b' ^ X, b'g' ^ X],
        &[b'I' ^ X, b'D' ^ X, b'A' ^ X, b' ' ^ X, b'-' ^ X, b' ' ^ X],
        &[
            b'I' ^ X, b'm' ^ X, b'm' ^ X, b'u' ^ X, b'n' ^ X, b'i' ^ X, b't' ^ X,
            b'y' ^ X, b' ' ^ X, b'D' ^ X, b'e' ^ X, b'b' ^ X, b'u' ^ X, b'g' ^ X,
            b'g' ^ X, b'e' ^ X, b'r' ^ X,
        ],
        &[b'W' ^ X, b'i' ^ X, b'n' ^ X, b'D' ^ X, b'b' ^ X, b'g' ^ X],
    ];
    RAW.iter()
        .map(|row| row.iter().map(|&b| (b ^ X) as char).collect())
        .collect()
}

#[cfg(target_os = "windows")]
fn window_debugger_present() -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowTextW, IsWindowVisible,
    };
    unsafe extern "system" fn cb(
        h: windows_sys::Win32::Foundation::HWND,
        lparam: windows_sys::Win32::Foundation::LPARAM,
    ) -> i32 {
        let flag = lparam as *mut bool;
        if IsWindowVisible(h) != 0 {
            let mut buf = [0u16; 128];
            let n = GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32);
            if n > 0 {
                let s = String::from_utf16_lossy(&buf[..n as usize]);
                // M5: debugger titles are stored XORed (^ 0x0d) so a static
                // scan of the binary does not reveal the match list.
                for pat in xor_patterns() {
                    if s.contains(pat.as_str()) {
                        *flag = true;
                        return 0;
                    }
                }
            }
        }
        1
    }
    let mut flag = false;
    unsafe {
        EnumWindows(Some(cb), &mut flag as *mut bool as isize);
    }
    flag
}

/// M5: runtime-unmask a small constant string. The stored bytes are XORed with
/// a fixed 0x5a so a static scan of the binary does not immediately show
/// sensitive literals (signature magic, debugger window titles).
fn xor_unmask<const N: usize>(xored: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = xored[i] ^ 0x5a;
    }
    out
}

/// M6: verify the embedded VM program blob matches its build-time hash. A
/// runtime memory patch of the VM bytecode (which would otherwise silently
/// change the key-rebuilding VM) is answered with a refusal to run.
fn verify_blob_integrity() -> bool {
    let actual = blake3::hash(VM_PROG_BLOB);
    crypto::ct_eq(actual.as_bytes(), VM_PROG_HASH)
}

/// Full-file Ed448 self-signature check. The build pipeline (cargo xtask sign)
/// appends a signature block to the PE overlay: magic(8) | covered_len(u64) |
/// verifying_key(57) | signature(114). `covered` is the number of leading bytes
/// that were signed. At runtime we re-read the running exe, locate the trailing
/// block, and verify [0..covered) with the embedded key.
fn verify_self_signature() -> bool {
    const MAGIC_X: &[u8; 8] = &[
        b'H' ^ 0x5a, b'L' ^ 0x5a, b'D' ^ 0x5a, b'L' ^ 0x5a,
        b'S' ^ 0x5a, b'I' ^ 0x5a, b'G' ^ 0x5a, b'1' ^ 0x5a,
    ];
    let magic = xor_unmask(MAGIC_X); // -> "HLDLSIG1"
    let data = match std::env::current_exe().and_then(|p| std::fs::read(p)) {
        Ok(d) => d,
        Err(_) => return false,
    };
    if data.len() < 8 + 8 + 57 + 114 {
        return false;
    }
    let block_off = data.len() - (8 + 8 + 57 + 114);
    if &data[block_off..block_off + 8] != &magic {
        return false;
    }
    let mut covered = [0u8; 8];
    covered.copy_from_slice(&data[block_off + 8..block_off + 16]);
    let covered = u64::from_le_bytes(covered) as usize;
    if covered > block_off {
        return false;
    }
    let mut vk_bytes = [0u8; 57];
    vk_bytes.copy_from_slice(&data[block_off + 16..block_off + 16 + 57]);
    let Ok(vk) = ed448_goldilocks::VerifyingKey::from_bytes(&vk_bytes) else {
        return false;
    };
    let sig_bytes = &data[block_off + 16 + 57..block_off + 16 + 57 + 114];
    let sig = ed448_goldilocks::Signature::from_bytes(
        sig_bytes.try_into().expect("sig len"),
    );
    vk.verify_raw(&sig, &data[..covered]).is_ok()
}

/// Lightweight debugger-presence probe shared by startup and the watchdog.
/// No timing measurement (the watchdog runs it on its own thread where a
/// scheduling hiccup would false-trigger), no process-wide side effects.
pub(crate) fn debugger_present() -> bool {
    if watchdog::tracer_pid() != 0 {
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            CheckRemoteDebuggerPresent, IsDebuggerPresent,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        if unsafe { IsDebuggerPresent() } != 0 {
            return true;
        }
        // Bypass any IsDebuggerPresent hook by reading the PEB flag directly.
        // gs:0x60 on x64 points at the PEB; BeingDebugged is at PEB+2.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let peb: *const u8;
            std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
            let bd = *peb.add(2);
            if bd != 0 {
                return true;
            }
        }
        let mut present: i32 = 0;
        unsafe {
            CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut present);
        }
        if present != 0 {
            return true;
        }
        // NtQueryInformationProcess probes: ProcessDebugPort (7),
        // ProcessDebugObjectHandle (0x1e), ProcessDebugFlags (0x1f).
        unsafe {
            type NtQueryInformationProcess = unsafe extern "system" fn(
                windows_sys::Win32::Foundation::HANDLE,
                u32,
                *mut std::ffi::c_void,
                u32,
                *mut u32,
            ) -> i32;
            if let Some(ntqi) = get_ntdll_proc("NtQueryInformationProcess") {
                let f: NtQueryInformationProcess = std::mem::transmute(ntqi);
                // ProcessDebugPort
                let mut debug_port: usize = 0;
                let mut ret = 0u32;
                let st = f(GetCurrentProcess(), 7, &mut debug_port as *mut _ as *mut _, 8, &mut ret);
                if st == 0 && debug_port != 0 {
                    return true;
                }
                // ProcessDebugObjectHandle
                let mut obj_handle: *mut std::ffi::c_void = std::ptr::null_mut();
                ret = 0;
                let st_obj = f(
                    GetCurrentProcess(),
                    0x1e,
                    &mut obj_handle as *mut _ as *mut _,
                    std::mem::size_of::<*mut std::ffi::c_void>() as u32,
                    &mut ret,
                );
                if st_obj == 0 && !obj_handle.is_null() {
                    return true;
                }
                // ProcessDebugFlags: 0 when debugged, nonzero when not.
                let mut no_debug = 0u32;
                ret = 0;
                let st_fl = f(
                    GetCurrentProcess(),
                    0x1f,
                    &mut no_debug as *mut _ as *mut _,
                    4,
                    &mut ret,
                );
                if st_fl == 0 && no_debug == 0 {
                    return true;
                }
            }
        }
        // Flag the common GUI debuggers by enumerating visible top-level
        // windows and matching their titles.
        if window_debugger_present() {
            return true;
        }
    }
    false
}

pub(crate) fn anti_debug_checks() -> bool {
    if debugger_present() {
        return false;
    }
    #[cfg(target_os = "linux")]
    unsafe {
        let _ = libc::prctl(libc::PR_SET_PTRACER, 0, 0, 0, 0);
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

    if !verify_self_signature() {
        eprintln!(
            "\nWARNING: executable integrity check failed.\n\
             This build is not signed or has been modified.\n\
             Refusing to run.\n"
        );
        std::process::exit(138);
    }

    if !verify_blob_integrity() {
        eprintln!(
            "\nWARNING: embedded VM program integrity check failed.\n\
             This build has been tampered with.\n\
             Refusing to run.\n"
        );
        std::process::exit(139);
    }

    signal::ignore();
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        libc::prctl(0x59616d61, 0, 0, 0, 0);
    }

    // M3: raise process mitigation policies (dynamic-code, strict-handle, ASLR).
    harden::raise_process_mitigations();

    if !harden::check_injection() {
        refuse(
            &["INJECTION DETECTED".to_string(), "Access denied".to_string()],
            &noop,
        );
    }

    // X6: degrade (slow + warn) under a virtualized environment.
    if harden::vm_detected() {
        rustyvm::set_vm_slow(true);
        eprintln!(
            "WARNING: virtualized environment detected — degraded mode (slowed) in effect."
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
                    // No TTY: no password can arrive. Exit cleanly instead of
                    // self-destructing — the door simply stays shut.
                    tui::show_cursor();
                    std::process::exit(1);
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
                // Symmetric timing: the success path burns the same cycles as
                // the failure path so a correct password cannot be identified
                // by how much faster it returned.
                timing_equalize();
                timing_jitter();
                prog = p;
                break;
            }
            None => {
                zeroize(&mut bk);
                if !std::io::stdin().is_terminal() {
                    // No TTY: no retry will help. Exit cleanly.
                    tui::show_cursor();
                    std::process::exit(1);
                }
                timing_equalize();
                timing_jitter();
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
        watchdog::self_destruct();
    }
    zeroize(prog.as_mut_slice());
    unsafe {
        std::ptr::copy_nonoverlapping(keys.as_ptr(), key_buf.ptr, shared::KEY_LEN);
    }
    zeroize(&mut keys);
    crypto::flush_mem(key_buf.ptr, shared::KEY_LEN);
    for i in 0..5 {
        fx.draw(0.3 + i as f32 * 0.14, &noop);
        tui::sleep(50);
    }
    fx.advance();

    let key_sha = crypto::sha3_256(&key_copy64(&key_buf));
    let feed: Arc<Mutex<Instant>> = watchdog::start(key_sha, key_buf.ptr as usize, 64);
    #[cfg(target_os = "windows")]
    watchdog::prevent_termination();
    #[cfg(target_os = "windows")]
    watchdog::harden_exe();
    key_buf.lock_ro();
    let beat = || {
        *feed.lock().unwrap() = Instant::now();
        watchdog::beat_main();
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
        k1.copy_from_slice(&all[..32]);
        k2.copy_from_slice(&all[32..]);
        zeroize(&mut all);
    }

    let open_ts = {
        let mut blob = match crypto::decrypt(&k1, TS_BLOB) {
            Some(b) => b,
            None => { watchdog::self_destruct(); }
        };
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&blob[..8]);
        let ts = u64::from_le_bytes(arr);
        crypto::zeroize(blob.as_mut_slice());
        if !crypto::ct_eq(&ts.to_le_bytes(), &open_ts_ref().to_le_bytes()) {
            watchdog::self_destruct();
        }
        ts
    };
    // Arm the watchdog time gate now that the real opening timestamp is known.
    watchdog::set_open_ts(open_ts);

    {
        if !ts_guard_valid(open_ts) {
            watchdog::self_destruct();
        }
    }

    let now_u64 = ntp_now.floor() as u64;
    // First gate check. We do NOT bail here: the whole 7-layer decryption runs
    // regardless of whether the door is open, so an observer cannot tell from
    // runtime length / power / cache trace whether the door is locked. The
    // final verdict is applied only at reveal time (and re-verified after the
    // full decryption chain).
    let locked = !time_gate_open(now_u64, open_ts);
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
    // k1/k2 are spent: wipe them from the stack immediately.
    zeroize(&mut k1);
    zeroize(&mut k2);
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
        None => { watchdog::self_destruct(); }
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
        None => { watchdog::self_destruct(); }
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
        None => { watchdog::self_destruct(); }
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
        None => { watchdog::self_destruct(); }
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
        None => { watchdog::self_destruct(); }
    };
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_wrapped[..32]);
    crypto::zeroize(dek_wrapped.as_mut_slice());
    crypto::zeroize(&mut serpent_dek_wrap_key);

    // Combine shards: RSA ^ Kyber ^ McEliece ^ FrodoKEM ^ Dilithium ^ SM3
    // Dilithium shard is blake3 hash of public key; SM3 shard is sm3 hash of
    // the same public key — two independent hash primitives over the VK.
    let dilithium_pk_hash_bytes: [u8; 32] = *blake3::hash(dilithium_vk_bytes).as_bytes();
    let mut s_dilithium_arr = [0u8; 32];
    s_dilithium_arr.copy_from_slice(&dilithium_pk_hash_bytes);

    let sm3_vk_hash_bytes: [u8; 32] = crypto::sm3_256(dilithium_vk_bytes);
    let mut s_sm3_arr = [0u8; 32];
    s_sm3_arr.copy_from_slice(&sm3_vk_hash_bytes);

    let mut combined_dek = xor6(&s_rsa_arr, &s_ky_arr, &s_mce_arr, &s_frodo_arr, &s_dilithium_arr, &s_sm3_arr);
    crypto::zeroize(&mut s_sm3_arr);
    
    // Constant-time compare DEK
    if !crypto::ct_eq(&combined_dek, &dek) {
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
        watchdog::self_destruct();
    }

    // Layer 8: Ed448 - verify signature
    fx.draw(0.8, &beat);
    let ed_vk = VerifyingKey::from_bytes(&ED_VK.try_into().expect("Ed448 VK len")).expect("Ed448 VK parse");
    let ed_sig = ed448_goldilocks::Signature::from_bytes(&ED_SIG.try_into().expect("Ed448 sig len"));
    if ed_vk.verify_raw(&ed_sig, &verify_msg).is_err() {
        watchdog::self_destruct();
    }

    // Decrypt Serpent-256-SIV payload
    fx.draw(0.9, &beat);
    let mut content = siv_decrypt(&combined_dek, &open_ts.to_le_bytes(), SIV_BLOB)
        .expect("SIV decrypt failed");
    crypto::zeroize(&mut combined_dek);

    // The sealed payload is [meta_len][meta_json][text]; pull out the metadata.
    let mut meta_lines: Vec<String> = Vec::new();
    let mut text = Vec::new();
    if content.len() >= 4 {
        let meta_len = u32::from_le_bytes([content[0], content[1], content[2], content[3]]) as usize;
        if content.len() >= 4 + meta_len {
            let meta_json = &content[4..4 + meta_len];
            meta_lines = parse_meta(meta_json);
            text.extend_from_slice(&content[4 + meta_len..]);
        } else {
            text.extend_from_slice(&content[4..]);
        }
    } else {
        text.extend_from_slice(&content);
    }

    // Copy content into secure buffer
    beat();
    unsafe {
        std::ptr::copy_nonoverlapping(text.as_ptr(), content_buf.ptr, text.len());
    }
    crypto::flush_mem(content_buf.ptr, text.len());
    crypto::zeroize(content.as_mut_slice());
    scrub_stack();
    // X2: keep the decrypted content ciphertext-at-rest in the secure buffer;
    // the mask is rotated by the watchdog until we are ready to display.
    rolling::arm(content_buf.ptr, text.len());

    fx.finish(&beat);

    // Second gate check: re-read the wall clock after the full decryption
    // chain so a system clock jump made mid-decrypt cannot slip past. If the
    // door is locked we still ran every layer above, so this branch does not
    // leak the door state through runtime length.
    if locked || !time_gate_open(ntp::unix_now_u64(), open_ts) {
        let mut lines = report.clone();
        lines.push("DOOR IS LOCKED".to_string());
        lines.push(format!("Opens at     {}", format_unix(open_ts)));
        lines.push("Time has not yet arrived".to_string());
        refuse(&lines, &beat);
    }

    // Success sequence and display
    success_sequence(&beat);

    // X2: decrypt the content back for display. The plaintext is exposed only
    // here, briefly, then the rolling cipher is disarmed and the mask wiped.
    rolling::disarm();
    let revealed = unsafe { std::slice::from_raw_parts(content_buf.ptr, text.len()) };
    let mut revealed = String::from_utf8_lossy(revealed).into_owned();
    let mut all = report;
    for line in meta_lines {
        all.push(line);
    }
    for line in revealed.lines() {
        all.push(line.to_string());
    }
    // Wipe the owned copy now that every line has been copied into `all`.
    unsafe {
        let v = revealed.as_mut_vec();
        for b in v.iter_mut() {
            std::ptr::write_volatile(b, 0);
        }
    }
    drop(revealed);
    // Re-encrypt the secure buffer: plaintext residency was limited to the copy
    // above; from here on the buffer holds rotating ciphertext again until exit.
    rolling::arm(content_buf.ptr, text.len());

    beat();
    let unlock_time = format_unix(open_ts);
    let burn = tui::show(&all, &beat, &unlock_time, true);
    if burn {
        let width = tui::term_width();
        let height = tui::term_height();
        watchdog::stop();
        tui::burn_with_progress(width, height, &beat);
        // Wipe the (masked) content in the secure buffer before locking it away.
        rolling::disarm();
        unsafe {
            let b = std::slice::from_raw_parts_mut(content_buf.ptr, text.len());
            for x in b.iter_mut() {
                std::ptr::write_volatile(x, 0);
            }
        }
        crypto::flush_mem(content_buf.ptr, text.len());
        key_buf.lock_none();
        content_buf.lock_none();

        // Zeroize content before exit
        crypto::zeroize(content.as_mut_slice());

        // The user confirmed the burn: release the exe lock first, then remove
        // the binary and the diagnostic log we may have written during this run.
        watchdog::unlock_exe();
        if let Ok(exe) = std::env::current_exe() {
            let _ = std::fs::remove_file(exe);
        }
        #[cfg(target_os = "windows")]
        {
            let log = std::env::temp_dir().join("hello_old_destruct.log");
            let _ = std::fs::remove_file(log);
        }
    } else {
        // keep terminal stable after a wrong-letter cancel, but still wipe the
        // decrypted content from the secure buffer before exiting.
        rolling::disarm();
        unsafe {
            let b = std::slice::from_raw_parts_mut(content_buf.ptr, text.len());
            for x in b.iter_mut() {
                std::ptr::write_volatile(x, 0);
            }
        }
        crypto::flush_mem(content_buf.ptr, text.len());
        content_buf.lock_none();
        tui::show_cursor();
        std::process::exit(0);
    }
}

fn zeroize(buf: &mut [u8]) {
    crypto::zeroize(buf);
}

/// Wipe a large volatile stack region so secret intermediates (shard arrays,
/// derived keys) that a compiler keeps in stack slots do not survive into the
/// next frame where a different code path could read them.
fn scrub_stack() {
    let mut page = [0u8; 4096];
    for b in page.iter_mut() {
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    crypto::zeroize(&mut page);
}

use tui::{C_RESET, C_CYAN, C_GREEN, C_RED, C_YELLOW, C_BRIGHT_WHITE};