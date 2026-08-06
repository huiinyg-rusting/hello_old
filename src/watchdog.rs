use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::crypto;

static RUNNING: AtomicBool = AtomicBool::new(true);

pub fn stop() {
    RUNNING.store(false, Ordering::SeqCst);
}

pub fn self_destruct() -> ! {
    loop {
        unsafe {
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn tracer_pid() -> u32 {
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
    std::thread::spawn(move || {
        while RUNNING.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(400));
            let stale = f.lock().unwrap().elapsed().as_secs() > 6;
            let traced = tracer_pid() != 0;
            if stale || traced {
                self_destruct();
            }
            if read_self_exe_sha() != exe_sha {
                self_destruct();
            }
            let mut actual = [0u8; 64];
            unsafe {
                if key_len > 64 {
                    self_destruct();
                }
                std::ptr::copy_nonoverlapping(key_ptr as *const u8, actual.as_mut_ptr(), key_len);
            }
            if crypto::sha3_256(&actual[..key_len]) != expected_key_sha {
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
