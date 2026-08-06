pub fn check_injection() -> bool {
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
    maps_rwx_clean()
}

fn maps_has_loader() -> bool {
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return false;
    };
    maps.lines().any(|l| l.contains("ld-musl") || l.contains("-linux-gnu.so"))
}

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

fn mono() -> f64 {
    unsafe {
        let mut t: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t);
        t.tv_sec as f64 + t.tv_nsec as f64 / 1e9
    }
}

fn wall() -> f64 {
    unsafe {
        let mut t: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut t);
        t.tv_sec as f64 + t.tv_nsec as f64 / 1e9
    }
}
