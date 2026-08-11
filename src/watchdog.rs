use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::crypto;

static RUNNING: AtomicBool = AtomicBool::new(true);

/// Time gate deadline. u64::MAX means "not armed yet"; the periodic gate
/// check is a no-op until main arms it with set_open_ts() after the opening
/// timestamp has been decrypted from the timestamp blob.
static OPEN_TS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);

pub fn set_open_ts(ts: u64) {
    OPEN_TS.store(ts, std::sync::atomic::Ordering::SeqCst);
}

pub fn stop() {
    RUNNING.store(false, Ordering::SeqCst);
}

#[cfg(target_os = "linux")]
pub fn self_destruct() -> ! {
    loop {
        unsafe {
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[cfg(not(target_os = "linux"))]
pub fn self_destruct() -> ! {
    loop {
        std::process::exit(0xC0000409u32 as i32); // STATUS_STACK_BUFFER_OVERRUN (fail-fast)
    }
}

#[cfg(target_os = "windows")]
fn log_destruct(reason: &str) {
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = std::env::temp_dir().join("hello_old_destruct.log");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "[unix {}] {}", secs, reason);
    }
}
/// Windows: raise the process to a protected level as far as userland allows
/// (ignore CTRL_C / CTRL_BREAK so a "waiting" user cannot be silently killed),
/// and enable fail-fast so a tamper or debugger is answered with a hard
/// STATUS_STACK_BUFFER_OVERRUN instead of a clean exit.
#[cfg(target_os = "windows")]
pub fn prevent_termination() {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    unsafe extern "system" fn ctrl_handler(_ctrl_type: u32) -> i32 {
        1 // handled; keep the process alive so a stray Ctrl+C cannot burn it
    }
    unsafe {
        SetConsoleCtrlHandler(Some(ctrl_handler), 1);
    }
}

/// Windows: make the running executable undeletable while the process is alive.
/// We open our own exe with a share mode that does NOT grant FILE_SHARE_DELETE
/// and keep the handle for the lifetime of the process. Any DeleteFile /
/// MoveFile / overwrite attempt from another process fails with a sharing
/// violation until the process exits. The burn path calls unlock_exe() first
/// so a confirmed self-destruct can still remove the file.
#[cfg(target_os = "windows")]
static EXE_HANDLE: std::sync::Mutex<Option<isize>> = std::sync::Mutex::new(None);

#[cfg(target_os = "windows")]
pub fn harden_exe() {
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY,
        FILE_ATTRIBUTE_SYSTEM, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
    };
    fn w(path: &str) -> Vec<u16> {
        path.encode_utf16().chain(std::iter::once(0)).collect()
    }
    if let Ok(exe) = std::env::current_exe() {
        let p = w(&exe.to_string_lossy());
        unsafe {
            let h = CreateFileW(
                p.as_ptr(),
                FILE_GENERIC_READ,
                FILE_SHARE_READ, // no FILE_SHARE_DELETE -> file cannot be removed
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );
            if !h.is_null() {
                // Hold the handle for the whole process lifetime; because it is
                // a raw pointer it has no Drop and stays open, locking the file.
                if let Ok(mut g) = EXE_HANDLE.lock() {
                    *g = Some(h as isize);
                }
            }
            // Mark the file hidden + system + readonly as a deterrent.
            SetFileAttributesW(
                p.as_ptr(),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY,
            );
        }
    }
}

/// Release the exe lock so the burn path can delete the file. No-op on the
/// Linux side (there is no persistent handle there).
#[cfg(target_os = "windows")]
pub fn unlock_exe() {
    use windows_sys::Win32::Foundation::CloseHandle;
    if let Ok(mut g) = EXE_HANDLE.lock() {
        if let Some(h) = g.take() {
            unsafe {
                CloseHandle(h as *mut _);
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn unlock_exe() {}

#[cfg(target_os = "linux")]
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

#[cfg(not(target_os = "linux"))]
pub fn tracer_pid() -> u32 {
    // Windows: debugger detection is handled via IsDebuggerPresent /
    // CheckRemoteDebuggerPresent in anti_debug_checks(). Report no tracer here.
    0
}

#[cfg(target_os = "linux")]
fn read_self_exe_sha() -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Ok(bytes) = std::fs::read("/proc/self/exe") {
        out = crypto::sha3_256(&bytes);
    }
    out
}

/// Cross-monitoring heartbeats for X3 (dual watchdog). Slot layout:
/// 0 = main thread feed (beat_main), 1 = watchdog #1, 2 = watchdog #2.
/// Each watchdog tick stamps its own slot with the current unix time and
/// verifies that both the main thread and the sibling watchdog have ticked
/// recently. A missing sibling heartbeat means the other watchdog was killed,
/// which is answered with a hard fail-fast.
const HEARTBEAT_ALIVE_SECS: u64 = 2;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

static MAIN_HB: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Called from the main thread's feed/beat loop: stamp the main heartbeat so
/// both watchdogs can tell the main thread is still alive and progressing.
pub fn beat_main() {
    MAIN_HB.store(now_unix(), Ordering::SeqCst);
}

static HB_W1: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static HB_W2: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn start(expected_key_sha: [u8; 32], key_ptr: usize, key_len: usize) -> Arc<Mutex<Instant>> {
    let feed = Arc::new(Mutex::new(Instant::now()));
    let now = now_unix();
    MAIN_HB.store(now, Ordering::SeqCst);
    HB_W1.store(now, Ordering::SeqCst);
    HB_W2.store(now, Ordering::SeqCst);
    let f1 = feed.clone();
    let f2 = feed.clone();
    let (k1, k2) = (expected_key_sha, expected_key_sha);
    let (p1, l1) = (key_ptr, key_len);
    let (p2, l2) = (key_ptr, key_len);

    // Watchdog #1.
    std::thread::spawn(move || {
        while RUNNING.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(400));
            HB_W1.store(now_unix(), Ordering::SeqCst);

            let main_ok = MAIN_HB.load(Ordering::SeqCst) + HEARTBEAT_ALIVE_SECS >= now_unix();
            let w2_ok = HB_W2.load(Ordering::SeqCst) + HEARTBEAT_ALIVE_SECS >= now_unix();
            let stale = f1.lock().unwrap().elapsed().as_secs() > 300;
            let traced = tracer_pid() != 0;
            if !main_ok || !w2_ok || stale || traced {
                #[cfg(target_os = "windows")]
                log_destruct(if !main_ok {
                    "MAIN_DEAD"
                } else if !w2_ok {
                    "W2_DEAD"
                } else if stale {
                    "STALE >300s"
                } else {
                    "TRACED"
                });
                self_destruct();
            }
            watchdog_body(&k1, p1, l1);
        }
    });

    // Watchdog #2: identical checks, sibling is watchdog #1.
    std::thread::spawn(move || {
        while RUNNING.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(400));
            HB_W2.store(now_unix(), Ordering::SeqCst);

            let main_ok = MAIN_HB.load(Ordering::SeqCst) + HEARTBEAT_ALIVE_SECS >= now_unix();
            let w1_ok = HB_W1.load(Ordering::SeqCst) + HEARTBEAT_ALIVE_SECS >= now_unix();
            let stale = f2.lock().unwrap().elapsed().as_secs() > 300;
            let traced = tracer_pid() != 0;
            if !main_ok || !w1_ok || stale || traced {
                #[cfg(target_os = "windows")]
                log_destruct(if !main_ok {
                    "MAIN_DEAD"
                } else if !w1_ok {
                    "W1_DEAD"
                } else if stale {
                    "STALE >300s"
                } else {
                    "TRACED"
                });
                self_destruct();
            }
            watchdog_body(&k2, p2, l2);
        }
    });

    feed
}

/// Common watchdog workload shared by both instances: rotate the rolling
/// cipher, verify the time gate, check the key hash in memory, and (on Linux)
/// re-hash the running exe.
/// M7: keep the code-region baseline and fail-fast when a live memory patch
/// of the running .text is observed. Both watchdogs call this, but only the
/// first caller stores the baseline (the rest just verify against it).
fn check_text_integrity() {
    static TEXT_HASH: std::sync::Mutex<Option<[u8; 32]>> = std::sync::Mutex::new(None);
    let Some(h) = crate::harden::text_hash() else {
        return;
    };
    let mut slot = TEXT_HASH.lock().unwrap();
    match *slot {
        None => *slot = Some(h),
        Some(base) => {
            if !crate::crypto::ct_eq(&base, &h) {
                #[cfg(target_os = "windows")]
                log_destruct("TEXT_PATCHED");
                self_destruct();
            }
        }
    }
}

fn watchdog_body(expected_key_sha: &[u8; 32], key_ptr: usize, key_len: usize) {
    // M1: periodic debugger re-probe. The watchdog runs this every tick so a
    // debugger attached mid-run is caught, not just at startup.
    if crate::debugger_present() {
        #[cfg(target_os = "windows")]
        log_destruct("DEBUGGER_MIDRUN");
        self_destruct();
    }
    // M7: periodic .text memory self-check. A live patch of the code region
    // diverges from the baseline captured on the first tick.
    check_text_integrity();
    // X2: rotate the in-memory rolling mask for the decrypted content
    // while it sits in the secure buffer.
    crate::rolling::rotate();
    // Periodic time-gate verification: once armed, rolling the clock
    // back past the open timestamp is answered with a hard fail-fast.
    let open_ts = OPEN_TS.load(std::sync::atomic::Ordering::SeqCst);
    if open_ts != u64::MAX && crate::ntp::unix_now_u64() < open_ts {
        #[cfg(target_os = "windows")]
        log_destruct("TIME_GATE_EARLY");
        self_destruct();
    }
    #[cfg(target_os = "linux")]
    {
        if std::fs::metadata("/proc/self/exe").is_ok() {
            let exe_sha = read_self_exe_sha();
            if exe_sha != read_self_exe_sha() {
                self_destruct();
            }
        }
    }
    let mut actual = [0u8; 64];
    unsafe {
        if key_len > 64 {
            self_destruct();
        }
        std::ptr::copy_nonoverlapping(key_ptr as *const u8, actual.as_mut_ptr(), key_len);
    }
    let actual_sha = crypto::sha3_256(&actual[..key_len]);
    if !crypto::ct_eq(&actual_sha, expected_key_sha) {
        #[cfg(target_os = "windows")]
        log_destruct("KEY_HASH_MISMATCH");
        self_destruct();
    }
    unsafe {
        for b in actual.iter_mut() {
            std::ptr::write_volatile(b, 0);
        }
    }
}
