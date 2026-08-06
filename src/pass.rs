use std::io::{IsTerminal, Read, Write};

pub fn read_password() -> Option<Vec<u8>> {
    if std::io::stdin().is_terminal() {
        unsafe {
            let fd = libc::STDIN_FILENO;
            let mut old: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut old) == 0 {
                let mut nw = old;
                nw.c_lflag &= !(libc::ECHO as libc::tcflag_t);
                nw.c_lflag &= !(libc::ICANON as libc::tcflag_t);
                if libc::tcsetattr(fd, libc::TCSANOW, &nw) == 0 {
                    let mut buf = Vec::new();
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
                                        return Some(buf);
                                    }
                                    if byte == 0x7f || byte == 0x08 {
                                        if !buf.is_empty() {
                                            buf.pop();
                                            print!("\x08 \x08");
                                            let _ = std::io::stdout().flush();
                                        }
                                        continue;
                                    }
                                    if byte >= 0x20 && byte <= 0x7e {
                                        buf.push(byte);
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
                    return Some(buf);
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