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

const PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.bin"));
const TS_BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ts.bin"));
const TS_PLAIN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ts_plain.bin"));
const VM_PROG_BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vmprog.bin"));
const KM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/km.bin"));
const SALT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/salt.bin"));

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
        tui::sleep(300);
    }
    
    tui::clear();
    
    for _ in 0..8 {
        for r in 1..=height {
            let g = rng.fill_line(width);
            tui::cursor(r, 1);
            print!("{}{}{}", C_GREEN, g, C_RESET);
        }
        tui::flush();
        tui::sleep(20);
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
    let mut prog;
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
    if !rustyvm::run(&prog, KM, &mut keys) {
        watchdog::self_destruct();
    }
    zeroize(prog.as_mut_slice());
    unsafe {
        std::ptr::copy_nonoverlapping(keys.as_ptr(), key_buf.ptr, shared::KEY_LEN);
    }
    zeroize(&mut keys);

    let key_sha = crypto::sha3_256(&key_copy64(&key_buf));
    let feed: Arc<Mutex<Instant>> = watchdog::start(key_sha, key_buf.ptr as usize, 64);
    key_buf.lock_ro();
    let beat = || {
        *feed.lock().unwrap() = Instant::now();
    };
    beat();

    let anchor = harden::ClockAnchor::new();
    if !anchor.sane() {
        refuse(
            &["Clock jump detected".to_string(), "Access denied".to_string()],
            &beat,
        );
    }

    if !seccomp::install() {
        refuse(
            &["seccomp install failed".to_string(), "Access denied".to_string()],
            &beat,
        );
    }

    beat();
    let mut report: Vec<String> = Vec::new();

    let local_now = ntp::unix_now_u64();
    let (local_year, _, _) = civil_from_days((local_now / 86400) as i64);
    if !(2020..=2100).contains(&local_year) {
        refuse(
            &["Local clock suspicious".to_string(), "Access denied".to_string()],
            &beat,
        );
    }

    report.push(format!("Local time    {}", format_unix(local_now)));

    let results = ntp::sync_all(&shared::NTP_SERVERS);
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
            None => watchdog::self_destruct(),
        };
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&blob[..8]);
        let ts = u64::from_le_bytes(arr);
        crypto::zeroize(blob.as_mut_slice());
        if !crypto::ct_eq(&ts.to_le_bytes(), &shared::OPEN_TIMESTAMP_UNIX_SECONDS.to_le_bytes()) {
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

    beat();
    let mut content = {
        let mut inner = match crypto::decrypt(&k1, PAYLOAD) {
            Some(c) => c,
            None => watchdog::self_destruct(),
        };
        let out = match crypto::decrypt(&k2, &inner) {
            Some(c) => c,
            None => watchdog::self_destruct(),
        };
        crypto::zeroize(inner.as_mut_slice());
        crypto::zeroize(&mut k1);
        crypto::zeroize(&mut k2);
        out
    };
    unsafe {
        std::ptr::copy_nonoverlapping(content.as_ptr(), content_buf.ptr, content.len());
    }
    let content_len = content.len();
    crypto::zeroize(content.as_mut_slice());
    drop(content);

    success_sequence(&beat);

    let text = unsafe { std::slice::from_raw_parts(content_buf.ptr, content_len) };
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
    print!("\x1b[{};{}H\x1b[2m{}\x1b[0m", hr, 1, format!("{}{}", " ".repeat(hpad), hint));
    flush_stdout();
    tui::wait_for_quit(&beat);

    watchdog::stop();
    let height = tui::term_height();
    tui::burn_with_progress(width, height, &beat);
    key_buf.lock_none();
    content_buf.lock_none();

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

use tui::{C_RESET, C_CYAN, C_GREEN, C_RED, C_YELLOW, C_BRIGHT_WHITE};