use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::io::Write;
use std::fs::OpenOptions;


use crate::crypto;

static RUNNING: AtomicBool = AtomicBool::new(true);

fn log_debug(msg: &str) {
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("/home/admin/gitHub/hello_old/watchdog_debug.log") {
        let _ = writeln!(f, "{}", msg);
        let _ = f.flush();
    } else {
        eprintln!("FAILED TO OPEN LOG FILE: {}", msg);
    }
}

pub fn stop() {
    RUNNING.store(false, Ordering::SeqCst);
}

pub fn self_destruct() -> ! {
    // Log that self_destruct is being invoked
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/home/admin/gitHub/hello_old/watchdog_debug.log") {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap()
            .as_secs();
        let thread_id = std::thread::current().id();
        let _ = writeln!(f, "self_destruct invoked at {} from thread {:?}", ts, thread_id);
        let _ = f.flush();
    }
    // If environment variable NO_SELF_DESTRUCT is set, exit gracefully for debugging
    if std::env::var("NO_SELF_DESTRUCT").is_ok() {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/home/admin/gitHub/hello_old/watchdog_debug.log") {
            let _ = writeln!(f, "NO_SELF_DESTRUCT branch taken, calling exit(1)");
            let _ = f.flush();
        }
        std::process::exit(1);
    }
    loop {
        unsafe {
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

pub fn tracer_pid() -> u32 {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("TracerPid:") {
                if let Ok(v) = rest.trim().parse::<u32>() {
                    return v;
                }
            }
        }
    }
    0
}

fn read_self_exe_sha() -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Ok(bytes) = std::fs::read("/proc/self/exe") {
        out = crypto::sha3_256(&bytes);
    }
    out
}

pub fn start(expected_key_sha: [u8; 32], key_ptr: usize, key_len: usize) -> Arc<Mutex<Instant>> {
    let feed = Arc::new(Mutex::new(Instant::now()));
    let f = feed.clone();
    let exe_sha = read_self_exe_sha();
    log_debug(&format!("watchdog thread started, exe_sha={:?}", exe_sha));
    std::thread::spawn(move || {
        while RUNNING.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(400));
            let stale = f.lock().unwrap().elapsed().as_secs() > 60;
            let traced = tracer_pid() != 0;
            log_debug(&format!("watchdog check: stale={}, traced={}", stale, traced));
            if stale || traced {
                log_debug(&format!("self_destruct: stale={}, traced={}", stale, traced));
                log_debug("ABOUT TO CALL SELF_DESTRUCT FROM STALE/TRACED");
                self_destruct();
            }
            if std::fs::metadata("/proc/self/exe").is_ok() {
                if read_self_exe_sha() != exe_sha {
                    log_debug("self_destruct: exe_sha changed");
                    log_debug("ABOUT TO CALL SELF_DESTRUCT FROM EXE_SHA");
                    self_destruct();
                }
            }
            let mut actual = [0u8; 64];
            unsafe {
            if key_len > 64 {
                log_debug("self_destruct: key_len > 64");
                log_debug("ABOUT TO CALL SELF_DESTRUCT FROM KEY_LEN");
                self_destruct();
            }
                std::ptr::copy_nonoverlapping(key_ptr as *const u8, actual.as_mut_ptr(), key_len);
            }
                if crypto::sha3_256(&actual[..key_len]) != expected_key_sha {
                    log_debug(&format!("self_destruct: key hash mismatch, actual={:?}, expected={:?}", 
                        crypto::sha3_256(&actual[..key_len]), expected_key_sha));
                    log_debug("ABOUT TO CALL SELF_DESTRUCT FROM KEY_HASH");
                    self_destruct();
                }
            unsafe {
                for b in actual.iter_mut() {
                    std::ptr::write_volatile(b, 0);
                }
            }
        }
    });
    feed
}
