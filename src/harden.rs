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

/// M3: raise Windows process-hardening mitigation policies at startup. Uses
/// dynamic loading so we do not depend on a specific windows-sys feature
/// surface, and applies best-effort policies: dynamic code policy (blocks
/// injected shellcode / runtime JIT), strict handle checks, and a bottom-up
/// ASLR preference. Each call is wrapped so a failure on an older OS is
/// silently ignored — hardening is additive, never a hard requirement.
pub fn raise_process_mitigations() {
    #[cfg(target_os = "windows")]
    unsafe {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        let k = std::ffi::OsStr::new("kernel32.dll")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();
        let kmod = GetModuleHandleW(k.as_ptr());
        if kmod.is_null() {
            return;
        }
        let name = std::ffi::CStr::from_bytes_with_nul(b"SetProcessMitigationPolicy\0").unwrap();
        let name_bytes = name.to_bytes();
        let Some(p) = GetProcAddress(kmod, name_bytes.as_ptr()) else {
            return;
        };
        let p = p as usize;
        if p == 0 {
            return;
        }
        type FnType = unsafe extern "system" fn(u32, *const std::ffi::c_void, usize) -> i32;
        let f: FnType = std::mem::transmute(p);

        // PROCESS_MITIGATION_POLICY IDs:
        //   0 DEP, 1 ASLR, 2 DynamicCode, 3 StrictHandle, 7 ControlFlowGuard,
        //   8 Signature, 10 ImageLoad. Each struct is a 4-byte DWORD union.
        // Best-effort: a policy that fails on an older OS is silently ignored.
        macro_rules! apply {
            ($pol:expr, $val:expr) => {
                let flags: u32 = $val;
                let data = flags.to_ne_bytes();
                let _ = f($pol, data.as_ptr() as *const _, data.len());
            };
        }

        // ASLR (1): bottom-up randomization + force-relocate + high-entropy VA.
        apply!(1, 0x0000_0007u32);

        // Dynamic code (2): ProhibitDynamicCode, disallow JIT / shellcode mapping.
        apply!(2, 0x0000_0001u32);

        // Strict handle checks (3): raise on invalid handle usage.
        apply!(3, 0x0000_0001u32);

        // Control Flow Guard (7): enforce CFG bitmap on indirect calls.
        apply!(7, 0x0000_0001u32);

        // Image load (10): no remote images, no low-mandatory-label images,
        // prefer System32. Blocks DLL hijacking / sideloading.
        apply!(10, 0x0000_0007u32);
    }
}

/// M7: hash the executable's own .text region from *memory*. Windows reads the
/// mapped module via the PE header; Linux reads the first r-x mapping from
/// /proc/self/maps. The watchdog keeps a baseline captured once at startup and
/// re-hashes periodically: a live memory patch of the running code diverges
/// from the baseline and triggers fail-fast. This complements X1 (file-level
/// signature, catches pre-launch tampering) by catching post-launch rewrites.
pub fn text_hash() -> Option<[u8; 32]> {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        unsafe {
            let m = GetModuleHandleW(std::ptr::null());
            if m.is_null() {
                return None;
            }
            let base = m as usize;
            let pe_off = *((base as *const u8).add(0x3c) as *const u32) as usize;
            let pe = (base + pe_off) as *const u8;
            // IMAGE_NT_HEADERS: Signature(4)+FileHeader(20)+OptionalHeader.
            // Section headers start after the optional header (PE32+: 240 bytes).
            let opt_size = *((pe.add(4 + 20) as *const u16)) as usize;
            let section_base = pe.add(4 + 20 + opt_size);
            let num_sections = *((pe.add(4 + 2) as *const u16)) as usize;
            let opt_magic = *((pe.add(4 + 20) as *const u16));
            let _ = opt_magic;
            let mut out = None;
            for i in 0..num_sections {
                let sh = section_base.add(i * 40);
                let name = std::slice::from_raw_parts(sh as *const u8, 8);
                if name == b".text\0\0\0" {
                    let vsize = *((sh.add(8) as *const u32)) as usize;
                    let vaddr = *((sh.add(12) as *const u32)) as usize;
                    let raw = std::slice::from_raw_parts((base + vaddr) as *const u8, vsize);
                    out = Some(crate::crypto::sha3_256(raw));
                }
            }
            return out;
        }
    }
    #[cfg(target_os = "linux")]
    {
        let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
        for line in maps.lines() {
            let mut it = line.split_whitespace();
            let (Some(range), Some(perms)) = (it.next(), it.next()) else {
                continue;
            };
            if perms.contains('x') && perms.contains('r') {
                if let Some((lo, hi)) = range.split_once('-') {
                    if let (Ok(lo), Ok(hi)) =
                        (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
                    {
                        let bytes = std::slice::from_raw_parts(lo as *const u8, hi - lo);
                        return Some(crate::crypto::sha3_256(bytes));
                    }
                }
            }
        }
        None
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        None
    }
}

/// Best-effort virtual-machine detection. Returns true when the current
/// environment shows strong hypervisor / VM fingerprints. Detection is
/// heuristic: it can be spoofed and can false-positive on sandboxed or
/// nested-virtualized hosts. Consumers should degrade (slow + warn), never
/// hard-fail on this signal.
pub fn vm_detected() -> bool {
    #[cfg(target_os = "linux")]
    {
        if std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| s.to_lowercase().contains("hypervisor"))
            .unwrap_or(false)
        {
            return true;
        }
        for p in [
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/product_version",
        ] {
            if let Ok(v) = std::fs::read_to_string(p) {
                let v = v.to_lowercase();
                if ["vmware", "virtualbox", "qemu", "kvm", "innotek", "xen", "vbox"]
                    .iter()
                    .any(|k| v.contains(k))
                {
                    return true;
                }
            }
        }
        false
    }
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::SystemInformation::GetSystemFirmwareTable;
        let mut buf = [0u8; 4096];
        unsafe {
            let sz = GetSystemFirmwareTable(0x41435049, 0, std::ptr::null_mut(), 0); // 'ACPI' RawSMBIOS
            if sz != 0 && (sz as usize) <= buf.len() {
                let got = GetSystemFirmwareTable(0x41435049, 0, buf.as_mut_ptr() as *mut _, sz);
                if got != 0 {
                    for k in ["vmware", "virtualbox", "qemu", "kvm", "vbox", "xen"] {
                        if find_case_insensitive(&buf[..got as usize], k.as_bytes()) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

/// Case-insensitive byte-sequence search.
fn find_case_insensitive(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| {
        w.iter()
            .zip(needle.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
    })
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
