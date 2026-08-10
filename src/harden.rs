pub fn check_injection() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(v) = std::env::var("LD_PRELOAD") {
            if !v.trim().is_empty() {
                return false;
            }
        }
        let is_dynamic = maps_has_loader();
        if !is_dynamic {
            if let Ok(v) = std::env::var("LD_LIBRARY_PATH") {
                if !v.trim().is_empty() {
                    return false;
                }
            }
        }
        return maps_rwx_clean();
    }
    #[cfg(not(target_os = "linux"))]
    {
        // No LD_PRELOAD / /proc/self/maps on Windows. DLL injection is mitigated
        // at the OS level; accept.
        let _ = std::env::var("LD_PRELOAD");
        true
    }
}

#[cfg(target_os = "linux")]
fn maps_has_loader() -> bool {
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return false;
    };
    maps.lines().any(|l| l.contains("ld-musl") || l.contains("-linux-gnu.so"))
}

#[cfg(target_os = "linux")]
fn maps_rwx_clean() -> bool {
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return true;
    };
    for line in maps.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.len() < 2 {
            continue;
        }
        let perms = toks[1];
        if perms.contains('w') && perms.contains('x') {
            return false;
        }
    }
    true
}

pub struct ClockAnchor {
    mono0: f64,
    wall0: f64,
}

impl ClockAnchor {
    pub fn new() -> Self {
        Self {
            mono0: mono(),
            wall0: wall(),
        }
    }

    pub fn sane(&self) -> bool {
        let expected = self.wall0 + (mono() - self.mono0);
        (wall() - expected).abs() < 2.0
    }
}

#[cfg(target_os = "linux")]
fn mono() -> f64 {
    unsafe {
        let mut t: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t);
        t.tv_sec as f64 + t.tv_nsec as f64 / 1e9
    }
}

#[cfg(target_os = "linux")]
fn wall() -> f64 {
    unsafe {
        let mut t: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut t);
        t.tv_sec as f64 + t.tv_nsec as f64 / 1e9
    }
}

// Windows: QueryPerformanceCounter (monotonic) and GetSystemTimePreciseAsFileTime
// (wall clock, 100ns since 1601, matching UNIX epoch after the standard offset).
#[cfg(target_os = "windows")]
fn mono() -> f64 {
    use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
    unsafe {
        let mut freq: i64 = 0;
        let mut count: i64 = 0;
        QueryPerformanceFrequency(&mut freq);
        QueryPerformanceCounter(&mut count);
        count as f64 / freq.max(1) as f64
    }
}

#[cfg(target_os = "windows")]
fn wall() -> f64 {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime;
    unsafe {
        let mut ft: FILETIME = std::mem::zeroed();
        GetSystemTimePreciseAsFileTime(&mut ft);
        let t = (((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64) as f64 / 10_000_000.0;
        t - 11_644_473_600.0
    }
}
