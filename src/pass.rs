use std::io::{IsTerminal, Read, Write};

pub const MAX_PASS_LEN: usize = 127;

pub fn read_password() -> Option<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        return read_password_linux();
    }
    #[cfg(target_os = "windows")]
    {
        return read_password_windows();
    }
}

/// Wipe the fixed-size scratch buffer used during a read.
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe {
            std::ptr::write_volatile(b, 0);
        }
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

/// Lock the password scratch page so it never swaps to disk while typed.
#[cfg(target_os = "windows")]
fn lock_page(ptr: *const u8, len: usize) {
    use windows_sys::Win32::System::Memory::VirtualLock;
    unsafe {
        VirtualLock(ptr as *const std::ffi::c_void, len);
    }
}

#[cfg(target_os = "linux")]
fn lock_page(ptr: *const u8, len: usize) {
    unsafe {
        libc::mlock(ptr as *const libc::c_void, len);
    }
}

#[cfg(target_os = "linux")]
fn read_password_linux() -> Option<Vec<u8>> {
    if std::io::stdin().is_terminal() {
        unsafe {
            let fd = libc::STDIN_FILENO;
            let mut old: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut old) == 0 {
                let mut nw = old;
                nw.c_lflag &= !(libc::ECHO as libc::tcflag_t);
                nw.c_lflag &= !(libc::ICANON as libc::tcflag_t);
                if libc::tcsetattr(fd, libc::TCSANOW, &nw) == 0 {
                    let mut buf = [0u8; MAX_PASS_LEN];
                    lock_page(buf.as_ptr(), buf.len());
                    let mut len = 0usize;
                    let mut chunk = [0u8; 64];
                    loop {
                        match std::io::stdin().read(&mut chunk) {
                            Ok(0) => break,
                            Ok(n) => {
                                for &byte in &chunk[..n] {
                                    if byte == b'\n' || byte == b'\r' {
                                        libc::tcsetattr(fd, libc::TCSANOW, &old);
                                        print!("\n");
                                        let _ = std::io::stdout().flush();
                                        let out = buf[..len].to_vec();
                                        wipe(&mut buf);
                                        return Some(out);
                                    }
                                    if byte == 0x7f || byte == 0x08 {
                                        if len > 0 {
                                            len -= 1;
                                            buf[len] = 0;
                                            print!("\x08 \x08");
                                            let _ = std::io::stdout().flush();
                                        }
                                        continue;
                                    }
                                    if byte >= 0x20 && byte <= 0x7e && len < buf.len() {
                                        buf[len] = byte;
                                        len += 1;
                                        print!("*");
                                        let _ = std::io::stdout().flush();
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    libc::tcsetattr(fd, libc::TCSANOW, &old);
                    print!("\n");
                    let _ = std::io::stdout().flush();
                    let out = buf[..len].to_vec();
                    wipe(&mut buf);
                    return Some(out);
                }
            }
        }
    }

    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return None;
    }
    Some(line.trim_end_matches(['\r', '\n']).as_bytes().to_vec())
}

// Windows: use the console input handle with ENABLE_ECHO_INPUT cleared so typed
// characters are not echoed, then read from stdin. Falls back to a plain
// read_line when not attached to a terminal (e.g. piped input). A fixed-size,
// page-locked scratch buffer keeps the password out of the heap and pagefile.
#[cfg(target_os = "windows")]
fn read_password_windows() -> Option<Vec<u8>> {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE, ENABLE_ECHO_INPUT,
        ENABLE_LINE_INPUT, STD_INPUT_HANDLE,
    };

    if std::io::stdin().is_terminal() {
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            if !handle.is_null() {
                let mut mode: CONSOLE_MODE = 0;
                if GetConsoleMode(handle, &mut mode) != 0 {
                    let new_mode = mode & !ENABLE_ECHO_INPUT & !ENABLE_LINE_INPUT;
                    if SetConsoleMode(handle, new_mode) != 0 {
                        let mut buf = [0u8; MAX_PASS_LEN];
                        lock_page(buf.as_ptr(), buf.len());
                        let mut len = 0usize;
                        let mut chunk = [0u8; 64];
                        loop {
                            match std::io::stdin().read(&mut chunk) {
                                Ok(0) => break,
                                Ok(n) => {
                                    for &byte in &chunk[..n] {
                                        if byte == b'\n' || byte == b'\r' {
                                            SetConsoleMode(handle, mode);
                                            print!("\n");
                                            let _ = std::io::stdout().flush();
                                            let out = buf[..len].to_vec();
                                            wipe(&mut buf);
                                            return Some(out);
                                        }
                                        if byte == 0x7f || byte == 0x08 {
                                            if len > 0 {
                                                len -= 1;
                                                buf[len] = 0;
                                                print!("\x08 \x08");
                                                let _ = std::io::stdout().flush();
                                            }
                                            continue;
                                        }
                                        if byte >= 0x20 && byte <= 0x7e && len < buf.len() {
                                            buf[len] = byte;
                                            len += 1;
                                            print!("*");
                                            let _ = std::io::stdout().flush();
                                        }
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        SetConsoleMode(handle, mode);
                        print!("\n");
                        let _ = std::io::stdout().flush();
                        let out = buf[..len].to_vec();
                        wipe(&mut buf);
                        return Some(out);
                    }
                }
            }
        }
    }

    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return None;
    }
    Some(line.trim_end_matches(['\r', '\n']).as_bytes().to_vec())
}
