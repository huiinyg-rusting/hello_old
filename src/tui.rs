use std::io::{self, IsTerminal, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const GLYPHS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz0123456789#@%&*+=!?$<>/\\|;:~^";

pub const C_RESET: &str = "\x1b[0m";
pub const C_DIM: &str = "\x1b[2m";
pub const C_GREEN: &str = "\x1b[32m";
pub const C_YELLOW: &str = "\x1b[33m";
pub const C_BRIGHT_WHITE: &str = "\x1b[97m";
pub const C_CYAN: &str = "\x1b[36m";
pub const C_RED: &str = "\x1b[31m";
pub const C_BG_DARK: &str = "\x1b[48;5;234m";
pub const C_BG_BLACK: &str = "\x1b[40m";

pub struct Rng(u64);

impl Rng {
    pub fn new() -> Self {
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mut r = t ^ 0x9E3779B97F4A7C15;
        let addr = &r as *const _ as u64;
        r ^= addr;
        Rng(r)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn glyph(&mut self) -> char {
        let i = (self.next_u64() as usize) % GLYPHS.len();
        GLYPHS[i] as char
    }
    pub fn fill(&mut self, width: usize) -> String {
        (0..width).map(|_| self.glyph()).collect()
    }
    pub fn fill_line(&mut self, width: usize) -> String {
        self.fill(width)
    }
}

#[cfg(target_os = "linux")]
pub fn term_width() -> usize {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 {
            ws.ws_col as usize
        } else {
            80
        }
    }
}

#[cfg(target_os = "linux")]
pub fn term_height() -> usize {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_row > 0 {
            ws.ws_row as usize
        } else {
            24
        }
    }
}

// Windows: query the console screen buffer via GetConsoleScreenBufferInfo.
#[cfg(target_os = "windows")]
pub fn term_width() -> usize {
    use windows_sys::Win32::System::Console::{
        GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO, STD_OUTPUT_HANDLE,
    };
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        if !h.is_null() {
            let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
            if GetConsoleScreenBufferInfo(h, &mut info) != 0 && info.srWindow.Right > info.srWindow.Left {
                return (info.srWindow.Right - info.srWindow.Left + 1) as usize;
            }
        }
        80
    }
}

#[cfg(target_os = "windows")]
pub fn term_height() -> usize {
    use windows_sys::Win32::System::Console::{
        GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO, STD_OUTPUT_HANDLE,
    };
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        if !h.is_null() {
            let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
            if GetConsoleScreenBufferInfo(h, &mut info) != 0 && info.srWindow.Bottom > info.srWindow.Top {
                return (info.srWindow.Bottom - info.srWindow.Top + 1) as usize;
            }
        }
        24
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn term_width() -> usize {
    80
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn term_height() -> usize {
    24
}

fn char_width(c: char) -> usize {
    let cp = c as u32;
    if (0x1100..=0x115F).contains(&cp)
        || (0x2E80..=0x303E).contains(&cp)
        || (0x3041..=0x33FF).contains(&cp)
        || (0x3400..=0x4DBF).contains(&cp)
        || (0x4E00..=0x9FFF).contains(&cp)
        || (0xA000..=0xA4CF).contains(&cp)
        || (0xAC00..=0xD7A3).contains(&cp)
        || (0xF900..=0xFAFF).contains(&cp)
        || (0xFE30..=0xFE4F).contains(&cp)
        || (0xFF00..=0xFF60).contains(&cp)
        || (0xFFE0..=0xFFE6).contains(&cp)
        || (0x20000..=0x2FFFD).contains(&cp)
        || (0x30000..=0x3FFFD).contains(&cp)
    {
        2
    } else {
        1
    }
}

pub fn display_width(s: &str) -> usize {
    let mut w = 0;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if let Some(n) = chars.next() {
                if n == '[' {
                    for c2 in chars.by_ref() {
                        let b = c2 as u32;
                        if (0x40..=0x7E).contains(&b) {
                            break;
                        }
                    }
                }
            }
        } else {
            w += char_width(c);
        }
    }
    w
}

pub fn sleep(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

pub fn cursor(row: usize, col: usize) {
    print!("\x1b[{};{}H", row, col);
}

pub fn flush() {
    let _ = io::stdout().flush();
}

pub fn clear() {
    print!("\x1b[2J\x1b[H");
    flush();
}

fn fill_bg_full(width: usize, height: usize) {
    print!("{}", C_BG_DARK);
    for r in 1..=height {
        cursor(r, 1);
        print!("{}", " ".repeat(width));
    }
    flush();
}

fn fullscreen_garble(width: usize, height: usize, frames: u32, ms: u64, rng: &mut Rng, feed: &dyn Fn()) {
    for _ in 0..frames {
        for r in 1..=height {
            let g = rng.fill_line(width);
            cursor(r, 1);
            print!("{}{}{}{}", C_BG_DARK, C_BRIGHT_WHITE, g, C_RESET);
        }
        flush();
        sleep(ms);
        feed();
    }
}

fn scanline_effect(width: usize, height: usize, rng: &mut Rng, feed: &dyn Fn()) {
    for r in 1..=height {
        let g = rng.fill_line(width);
        cursor(r, 1);
        print!("{}{}{}{}", C_BG_DARK, C_GREEN, g, C_RESET);
        flush();
        sleep(12);
        feed();
    }
    for r in (1..=height).rev() {
        let g = rng.fill_line(width);
        cursor(r, 1);
        print!("{}{}{}{}", C_BG_DARK, C_DIM, g, C_RESET);
        flush();
        sleep(8);
        feed();
    }
}

fn reveal_row_fast(row: usize, line: &str, width: usize, height: usize, unlock_time: &str, rng: &mut Rng, feed: &dyn Fn()) {
    let pad = center_pad(line, width);
    let chars: Vec<char> = line.chars().collect();
    let mut shown_w = 0usize;
    let mut revealed = String::new();

    for (i, &ch) in chars.iter().enumerate() {
        revealed.push(ch);
        shown_w += char_width(ch);
        let remain_w = width.saturating_sub(pad + shown_w);
        let g = rng.fill_line(remain_w);
        cursor(row, 1);
        print!(
            "{}{}{}{}{}{}{}{}",
            C_BG_DARK, C_DIM, " ".repeat(pad), C_GREEN, revealed, C_BRIGHT_WHITE, g, C_RESET
        );
        draw_status_bar(width, height, unlock_time);
        flush();
        sleep(10);
        if i % 3 == 0 {
            feed();
        }
    }
    cursor(row, 1);
    print!("{}{}{}{}", C_BG_DARK, C_DIM, " ".repeat(pad), C_GREEN);
    print!("{}", line);
    print!("{}{}", C_BG_DARK, " ".repeat(width.saturating_sub(pad + display_width(line))));
    draw_status_bar(width, height, unlock_time);
    flush();

    cursor(row, 1);
    print!("{}{}{}{}{}{}{}", C_BG_DARK, C_DIM, " ".repeat(pad), C_BRIGHT_WHITE, line, C_BG_DARK, " ".repeat(width.saturating_sub(pad + display_width(line))));
    flush();
    sleep(35);
    cursor(row, 1);
    print!("{}{}{}{}", C_BG_DARK, C_DIM, " ".repeat(pad), C_GREEN);
    print!("{}", line);
    print!("{}{}", C_BG_DARK, " ".repeat(width.saturating_sub(pad + display_width(line))));
    flush();
    sleep(18);
    feed();
}

fn draw_hline(row: usize, width: usize, color: &str) {
    cursor(row, 1);
    print!("{}{}{}{}", C_BG_DARK, color, std::iter::repeat('═').take(width).collect::<String>(), C_RESET);
    flush();
}

fn draw_status_bar(width: usize, height: usize, unlock_time: &str) {
    cursor(height, 1);
    let status = format!(" UNLOCK: {}  ", unlock_time);
    let pad = width.saturating_sub(status.len());
    print!("{}{}{}{}{}", C_BG_BLACK, C_YELLOW, status, " ".repeat(pad), C_RESET);
    flush();
}

fn draw_progress_bars_all(width: usize, height: usize, measures: &[(&str, f32)], current_idx: usize, progress: f32, feed: &dyn Fn()) {
    let start_row = (height.saturating_sub(measures.len() + 2)) / 2;
    
    for (i, (label, target)) in measures.iter().enumerate() {
        let row = start_row + i;
        cursor(row, 1);
        
        let bar_w = width.saturating_sub(label.len() + 13);
        let prog = if i < current_idx {
            *target
        } else if i == current_idx {
            progress * (*target)
        } else {
            0.0
        };
        let filled = ((bar_w as f32) * prog) as usize;
        let empty = bar_w.saturating_sub(filled);
        let pct = prog * 100.0;
        
        let color = if i < current_idx { C_GREEN } else if i == current_idx { C_YELLOW } else { C_DIM };
        
        print!("{}{}{:>2} {}{} [{}{}{}] {:>5.1}%", 
            C_BG_DARK, C_CYAN, i + 1, label, C_RESET,
            color, "█".repeat(filled), "░".repeat(empty), pct
        );
        let tail = width.saturating_sub(display_width(label) + bar_w + 13);
        print!("{}{}{}", C_BG_DARK, " ".repeat(tail), C_RESET);
    }
    flush();
    feed();
}

pub fn show(lines: &[String], feed: &dyn Fn(), unlock_time: &str, allow_burn: bool) -> bool {
    hide_cursor();
    let width = term_width();
    let height = term_height();
    let mut rng = Rng::new();

    fill_bg_full(width, height);
    fullscreen_garble(width, height, 20, 100, &mut rng, feed);
    scanline_effect(width, height, &mut rng, feed);

    fill_bg_full(width, height);
    draw_status_bar(width, height, unlock_time);

    let title = "█ TIME GATE █  OPENING THE DOOR  █ TIME GATE █";
    reveal_row_fast(1, title, width, height, unlock_time, &mut rng, feed);
    reveal_row_fast(2, &"──".to_string(), width, height, unlock_time, &mut rng, feed);
    draw_hline(3, width, C_CYAN);

    let body_top = 4;
    let body_bottom = height.saturating_sub(3);
    let per_page = body_bottom.saturating_sub(body_top) + 1;

    // Pre-wrap every line into display-width chunks that fit the terminal, then
    // group them into fixed-size pages. Pages are reused verbatim on repaint so
    // going "back" does not re-animate the reveal — it just re-renders the same
    // buffered text, which is instantaneous and keeps the story stable on screen
    // after a wrong-letter cancel.
    let mut content: Vec<String> = Vec::new();
    for line in lines {
        for chunk in wrap_line(line, width) {
            content.push(chunk);
        }
    }
    let mut pages: Vec<Vec<usize>> = Vec::new();
    let mut i = 0;
    while i < content.len() {
        let end = (i + per_page).min(content.len());
        pages.push((i..end).collect());
        i = end;
    }
    if pages.is_empty() {
        pages.push(Vec::new());
    }

    let is_tty = io::stdin().is_terminal();
    let mut page = 0usize;

    draw_page(&content, pages.get(page), body_top, body_bottom, &mut rng, feed);

    // Non-tty (piped/scripted) runs: render the first page and return without
    // entering an interactive loop.
    if !is_tty {
        return false;
    }

    loop {
        let hint = if !allow_burn {
            if pages.len() <= 1 {
                "  ▸ 按 q 退出  "
            } else {
                "  ▸ 按 空格/Enter 翻页  ·  p 返回上一页  ·  q 退出  "
            }
        } else if pages.len() <= 1 {
            "  ▸ 按 q 退出并烧毁  "
        } else {
            "  ▸ 按 空格/Enter 翻页  ·  p 返回上一页  ·  q 烧毁  "
        };
        let hp = center_pad(hint, width);
        cursor(body_bottom, 1);
        print!(
            "{}{}{}{}{}{}{}",
            C_BG_DARK, C_DIM, " ".repeat(hp), C_YELLOW, hint,
            " ".repeat(width.saturating_sub(hp + display_width(hint))), C_RESET
        );
        flush();

        match nav_wait(feed) {
            Nav::Next => {
                if page + 1 < pages.len() {
                    page += 1;
                    draw_page(&content, pages.get(page), body_top, body_bottom, &mut rng, feed);
                }
                // on the last page, Next just loops back silently
            }
            Nav::Prev => {
                if page > 0 {
                    page -= 1;
                    draw_page(&content, pages.get(page), body_top, body_bottom, &mut rng, feed);
                }
            }
            Nav::Burn => {
                if !allow_burn {
                    // Door not yet open: q just exits, never self-destructs.
                    return false;
                }
                let mut rng = Rng::new();
                let target = char::from(b'A' + (rng.next_u64() % 26) as u8);
                let ok = confirm_dialog(width, height, feed, target);
                if ok {
                    return true;
                }
                // wrong key: keep the story, repaint the current page
                draw_page(&content, pages.get(page), body_top, body_bottom, &mut rng, feed);
            }
        }

        // keep looping so q/p still work even on the final page
        feed();
    }
}

/// Static redraw of a single page (no reveal animation). Used both for the
/// initial render and for "previous page" / wrong-letter cancel repaints, so the
/// story stays readable on screen.
fn draw_page(content: &[String], page: Option<&Vec<usize>>, top: usize, bottom: usize, rng: &mut Rng, feed: &dyn Fn()) {
    let w = term_width();
    let mut row = top;
    if let Some(indices) = page {
        for &idx in indices {
            if row > bottom {
                break;
            }
            if idx < content.len() {
                let line = &content[idx];
                let pad = center_pad(line, w);
                cursor(row, 1);
                print!("{}{}{}{}{}{}", C_BG_DARK, C_DIM, " ".repeat(pad), C_GREEN, line, C_RESET);
                let remain = w.saturating_sub(pad + display_width(line));
                print!("{}{}", C_BG_DARK, " ".repeat(remain));
                flush();
            }
            row += 1;
        }
        // clear any leftover body rows from a previous longer page
        while row <= bottom {
            cursor(row, 1);
            print!("{}{}{}", C_BG_DARK, " ".repeat(w), C_RESET);
            row += 1;
        }
    }
    let _ = rng;
    feed();
}

enum Nav { Next, Prev, Burn }

// Returns true if a key is waiting to be read, polling stdin with a timeout so
// the watchdog feed can keep ticking. Cross-platform: poll() on Unix,
// WaitForSingleObject on the console input handle on Windows.
#[cfg(target_os = "linux")]
fn input_ready() -> bool {
    unsafe {
        let mut pfd = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        let r = libc::poll(&mut pfd, 1, 100);
        r > 0 && (pfd.revents & libc::POLLIN) != 0
    }
}

#[cfg(target_os = "windows")]
fn input_ready() -> bool {
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        if h.is_null() {
            return false;
        }
        WaitForSingleObject(h, 100) == WAIT_OBJECT_0
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn input_ready() -> bool {
    // No portable timeout-poll on other platforms; a blocking read would stall
    // the watchdog, so treat input as never ready and rely on non-tty handling.
    false
}

fn read_byte() -> Option<u8> {
    let mut b = [0u8; 1];
    match io::stdin().read(&mut b) {
        Ok(0) => None,
        Ok(_) => Some(b[0]),
        Err(_) => None,
    }
}

/// Wait for a navigation key while in raw mode.
/// space / Enter / →  = Next page, p / ← = Previous page, q = open burn dialog.
/// Non-tty input advances immediately (Next) so piped/scripted runs never block.
fn nav_wait(feed: &dyn Fn()) -> Nav {
    let tty = io::stdin().is_terminal();
    if !tty {
        feed();
        return Nav::Next;
    }
    let orig = raw_on();
    loop {
        if input_ready() {
            match read_byte() {
                Some(b' ') | Some(b'\n') | Some(b'\r') => {
                    raw_off(&orig);
                    return Nav::Next;
                }
                Some(b'p') | Some(b'P') => {
                    raw_off(&orig);
                    return Nav::Prev;
                }
                Some(b'q') | Some(b'Q') => {
                    raw_off(&orig);
                    return Nav::Burn;
                }
                Some(0x1b) => {
                    // possible arrow key CSI sequence: ESC [ <final>
                    let mut seq = [0u8; 2];
                    let n = io::stdin().read(&mut seq).unwrap_or(0);
                    if n == 2 && seq[0] == b'[' {
                        raw_off(&orig);
                        return match seq[1] {
                            b'C' => Nav::Next,
                            b'D' => Nav::Prev,
                            _ => Nav::Next,
                        };
                    } else if n == 0 {
                        raw_off(&orig);
                        return Nav::Next;
                    }
                    // not an arrow; treat as Next
                    raw_off(&orig);
                    return Nav::Next;
                }
                _ => {
                    continue;
                }
            }
        } else {
            feed();
            continue;
        }
    }
}


pub fn burn_with_progress(width: usize, height: usize, feed: &dyn Fn()) {
    let measures = [
        ("Wiping key memory", 1.0),
        ("Zeroing payload buffer", 1.0),
        ("Releasing guard pages", 1.0),
        ("Stopping watchdog", 1.0),
        ("Removing seccomp filter", 1.0),
        ("Deleting binary", 1.0),
        ("Clean exit", 1.0),
    ];
    
    let mut rng = Rng::new();

    // Phase 1: garble-typed warning line
    let msg = "INITIATING SELF-DESTRUCT SEQUENCE";
    let row = height / 2;
    let pad = center_pad(msg, width);
    let chars: Vec<char> = msg.chars().collect();
    fill_bg_full(width, height);
    draw_status_bar(width, height, "BURNING...");
    for (i, _) in chars.iter().enumerate() {
        for _ in 0..2 {
            cursor(row, 1);
            let left_g = rng.fill_line(pad);
            let right_g = rng.fill_line(width.saturating_sub(pad + display_width(msg)));
            let mut line = String::new();
            for (j, &c) in chars.iter().enumerate() {
                if j < i {
                    line.push(c);
                } else {
                    line.push(rng.glyph());
                }
            }
            print!("{}{}{}{}{}", C_BG_DARK, C_DIM, left_g, C_RED, line);
            print!("{}{}{}", C_BG_DARK, C_DIM, right_g);
            flush();
            sleep(30);
            feed();
        }
    }
    cursor(row, 1);
    print!("{}{}{}{}", C_BG_DARK, C_DIM, " ".repeat(pad), C_RED);
    print!("{}", msg);
    print!("{}{}{}", C_BG_DARK, " ".repeat(width.saturating_sub(pad + display_width(msg))), C_RESET);
    flush();

    // Phase 2: blinking cursor ~2s
    let blink_row = row + 2;
    for _ in 0..10 {
        cursor(blink_row, 1);
        let bp = center_pad("█", width);
        print!("{}{}{}{}{}{}", C_BG_DARK, C_DIM, " ".repeat(bp), C_YELLOW, "█", C_BG_DARK);
        print!("{}", " ".repeat(width.saturating_sub(bp + 1)));
        flush();
        sleep(110);
        cursor(blink_row, 1);
        print!("{}{}{}{}", C_BG_DARK, C_DIM, " ".repeat(bp), " ");
        print!("{}", " ".repeat(width.saturating_sub(bp + 1)));
        flush();
        sleep(90);
        feed();
    }

    // Phase 3: progress bars
    fill_bg_full(width, height);
    draw_status_bar(width, height, "BURNING...");
    for i in (0..measures.len()).rev() {
        for step in 0..=5 {
            let prog = 1.0 - (step as f32 / 5.0);
            draw_progress_bars_all(width, height, &measures, i, prog, feed);
            sleep(10);
        }
    }
    draw_progress_bars_all(width, height, &measures, 0, 0.0, feed);
    sleep(300);

    // Phase 4: garble flicker
    for _ in 0..3 {
        for r in 1..=height {
            let g = rng.fill_line(width);
            cursor(r, 1);
            print!("{}{}{}{}", C_BG_DARK, C_RED, g, C_RESET);
        }
        flush();
        sleep(45);
        feed();
    }

    clear();
    show_cursor();
}

pub fn dynamic_center_prompt(prompt: &str, feed: &dyn Fn()) {
    let width = term_width();
    let height = term_height();
    let prompt_w = display_width(prompt);
    let pad = (width.saturating_sub(prompt_w + 4)) / 2;
    let row = height / 2;
    
    let mut rng = Rng::new();
    
    fill_bg_full(width, height);
    draw_status_bar(width, height, "AWAITING PASSWORD");
    
    for _ in 0..10 {
        cursor(row, 1);
        let left_garble = rng.fill_line(pad);
        let right_garble = rng.fill_line(width.saturating_sub(pad + prompt_w + 4));
        print!("{}{}{}{}{}{}{}{}", C_BG_DARK, C_DIM, left_garble, C_CYAN, "  ", prompt, "  ", C_RESET);
        print!("{}{}{}", C_BG_DARK, C_DIM, right_garble);
        flush();
        sleep(45);
        feed();
    }
    
    cursor(row, 1);
    let left_pad = " ".repeat(pad);
    print!("{}{}{}{}{}{}{}", C_BG_DARK, C_DIM, left_pad, C_CYAN, "  ", prompt, "  ");
    print!("{}{}{}", C_BG_DARK, " ".repeat(width.saturating_sub(pad + prompt_w + 4)), C_RESET);
    draw_status_bar(width, height, "AWAITING PASSWORD");
    flush();
}

pub fn dynamic_center_error(msg: &str, feed: &dyn Fn()) {
    let width = term_width();
    let height = term_height();
    let msg_w = display_width(msg);
    let pad = (width.saturating_sub(msg_w + 4)) / 2;
    let row = height / 2 + 2;
    
    let mut rng = Rng::new();
    
    for _ in 0..7 {
        cursor(row, 1);
        let left_garble = rng.fill_line(pad);
        let right_garble = rng.fill_line(width.saturating_sub(pad + msg_w + 4));
        print!("{}{}{}{}{}{}{}{}", C_BG_DARK, C_DIM, left_garble, C_RED, "  ", msg, "  ", C_RESET);
        print!("{}{}{}", C_BG_DARK, C_DIM, right_garble);
        flush();
        sleep(40);
        feed();
    }
    
    for _ in 0..4 {
        cursor(row, 1);
        let left_pad = " ".repeat(pad);
        print!("{}{}{}{}{}{}{}", C_BG_DARK, C_DIM, left_pad, C_RED, "  ", msg, "  ");
        print!("{}{}{}", C_BG_DARK, " ".repeat(width.saturating_sub(pad + msg_w + 4)), C_RESET);
        flush();
        sleep(200);
        cursor(row, 1);
        print!("{}{}{}{}{}{}{}", C_BG_DARK, C_BRIGHT_WHITE, left_pad, C_RED, "  ", msg, "  ");
        print!("{}{}{}", C_BG_DARK, " ".repeat(width.saturating_sub(pad + msg_w + 4)), C_RESET);
        flush();
        sleep(200);
        feed();
    }
    
    cursor(row, 1);
    let left_pad = " ".repeat(pad);
    print!("{}{}{}{}{}{}{}", C_BG_DARK, C_DIM, left_pad, C_RED, "  ", msg, "  ");
    print!("{}{}{}", C_BG_DARK, " ".repeat(width.saturating_sub(pad + msg_w + 4)), C_RESET);
    flush();
    sleep(300);
}

pub fn dynamic_center_message(msg: &str, color: &str, feed: &dyn Fn()) {
    let width = term_width();
    let height = term_height();
    let msg_w = display_width(msg);
    let pad = (width.saturating_sub(msg_w + 4)) / 2;
    let row = height / 2;
    
    let mut rng = Rng::new();
    
    fill_bg_full(width, height);
    draw_status_bar(width, height, "PROCESSING...");
    
    for _ in 0..6 {
        cursor(row, 1);
        let left_garble = rng.fill_line(pad);
        let right_garble = rng.fill_line(width.saturating_sub(pad + msg_w + 4));
        print!("{}{}{}{}{}{}{}{}", C_BG_DARK, C_DIM, left_garble, color, "  ", msg, "  ", C_RESET);
        print!("{}{}{}", C_BG_DARK, C_DIM, right_garble);
        flush();
        sleep(35);
        feed();
    }
    
    cursor(row, 1);
    let left_pad = " ".repeat(pad);
    print!("{}{}{}{}{}{}{}", C_BG_DARK, C_DIM, left_pad, color, "  ", msg, "  ");
    print!("{}{}{}", C_BG_DARK, " ".repeat(width.saturating_sub(pad + msg_w + 4)), C_RESET);
    draw_status_bar(width, height, "PROCESSING...");
    flush();
}

pub struct DecryptFx {
    width: usize,
    height: usize,
    stages: Vec<String>,
    current: usize,
}

impl DecryptFx {
    pub fn new(width: usize, height: usize, stages: &[&str]) -> Self {
        DecryptFx {
            width,
            height,
            stages: stages.iter().map(|s| s.to_string()).collect(),
            current: 0,
        }
    }

    pub fn draw(&self, active: f32, feed: &dyn Fn()) {
        let w = self.width;
        let h = self.height;
        let n = self.stages.len();
        let panel_h = n + 4;
        let start = h.saturating_sub(panel_h) / 2 + 1;

        let mut rng = Rng::new();

        let title = "█ DECRYPTION SEQUENCE █";
        let title_w = display_width(title);
        let tpad = center_pad(title, w);
        cursor(start - 2, 1);
        print!("{}{}{}{}", C_BG_DARK, C_DIM, rng.fill_line(w), C_RESET);
        cursor(start - 1, 1);
        print!("{}{}{}{}{}{}", C_BG_DARK, C_CYAN, " ".repeat(tpad), title, " ".repeat(w.saturating_sub(tpad + title_w)), C_RESET);

        for (i, label) in self.stages.iter().enumerate() {
            let row = start + i;
            cursor(row, 1);
            let (marker, color) = if i < self.current {
                ("✓", C_GREEN)
            } else if i == self.current {
                ("▶", C_YELLOW)
            } else {
                (" ", C_DIM)
            };
            let mut line = format!(" {} [{:02}] {}", marker, i + 1, label);
            if i < self.current {
                line.push_str("  DONE");
            } else if i == self.current {
                let bw: usize = 14;
                let filled = ((bw as f32) * active.clamp(0.0, 1.0)) as usize;
                line.push_str(&format!("  [{}]", "█".repeat(filled) + &"░".repeat(bw.saturating_sub(filled))));
                if (rng.next_u64() % 3) == 0 {
                    line.push(' ');
                    line.push(rng.glyph());
                }
            }
            let remain = w.saturating_sub(display_width(&line));
            print!("{}{}{}{}", C_BG_DARK, color, line, " ".repeat(remain));
        }

        let bottom = start + n;
        cursor(bottom, 1);
        print!("{}{}{}{}", C_BG_DARK, C_CYAN, "═".repeat(w), C_RESET);
        cursor(bottom + 1, 1);
        print!("{}{}{}{}", C_BG_DARK, C_DIM, rng.fill_line(w), C_RESET);

        draw_status_bar(w, h, "PROCESSING...");
        flush();
        feed();
    }

    pub fn advance(&mut self) {
        if self.current < self.stages.len() {
            self.current += 1;
        }
    }

    pub fn finish(&self, feed: &dyn Fn()) {
        sleep(150);
        clear();
        flush();
        feed();
    }
}

pub fn hide_cursor() {
    print!("\x1b[?25l");
    flush();
}

pub fn show_cursor() {
    print!("\x1b[?25h");
    flush();
}

#[cfg(target_os = "linux")]
fn raw_on() -> libc::termios {
    unsafe {
        let mut orig: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(libc::STDIN_FILENO, &mut orig) == 0 {
            let mut nw = orig;
            nw.c_lflag &= !(libc::ICANON as libc::tcflag_t);
            nw.c_lflag &= !(libc::ECHO as libc::tcflag_t);
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &nw);
        }
        orig
    }
}

#[cfg(target_os = "linux")]
fn raw_off(orig: &libc::termios) {
    unsafe {
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, orig);
    }
}

// Windows raw mode: disable line-buffering/echo via SetConsoleMode.
#[cfg(target_os = "windows")]
fn raw_on() -> u32 {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE, ENABLE_ECHO_INPUT,
        ENABLE_LINE_INPUT, STD_INPUT_HANDLE,
    };
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        if h.is_null() {
            return 0;
        }
        let mut mode: CONSOLE_MODE = 0;
        if GetConsoleMode(h, &mut mode) != 0 {
            SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT & !ENABLE_LINE_INPUT);
        }
        mode
    }
}

#[cfg(target_os = "windows")]
fn raw_off(orig: &u32) {
    use windows_sys::Win32::System::Console::{GetStdHandle, SetConsoleMode, STD_INPUT_HANDLE};
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        if !h.is_null() {
            SetConsoleMode(h, *orig);
        }
    }
}

// Other Unixes: no portable raw mode; fall back to termios-like no-op types.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn raw_on() -> u8 {
    0
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn raw_off(_orig: &u8) {}

pub fn center_pad(line: &str, width: usize) -> usize {
    let w = display_width(line);
    if w >= width {
        return 0;
    }
    (width - w) / 2
}

/// Split a line into chunks that each fit within `width` display columns.
/// Splits on display width (CJK chars count as 2), never mid-char.
fn wrap_line(line: &str, width: usize) -> Vec<String> {
    if width == 0 || display_width(line) <= width {
        return vec![line.to_string()];
    }
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut cur_w = 0usize;
    for c in line.chars() {
        let cw = char_width(c);
        if cur_w + cw > width && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
            cur_w = 0;
        }
        cur.push(c);
        cur_w += cw;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[allow(dead_code)]
pub fn wait_for_quit(feed: &dyn Fn()) {
    let tty = io::stdin().is_terminal();
    if !tty {
        return;
    }
    let orig = raw_on();
    loop {
        if input_ready() {
            match read_byte() {
                Some(b'q') | Some(b'Q') => break,
                Some(_) => {}
                None => break,
            }
        } else {
            feed();
            continue;
        }
        feed();
    }
    raw_off(&orig);
    show_cursor();
}

/// Show a modal confirmation dialog and wait for the confirmation key.
/// Returns true if the user typed the target letter (case-insensitive),
/// false for any other key. Non-tty input auto-confirms so scripted runs
/// proceed without blocking.
pub fn confirm_dialog(width: usize, height: usize, feed: &dyn Fn(), target: char) -> bool {
    show_dialog(width, height, feed, target);
    confirm_burn(feed, target)
}

/// Wait for the confirmation key while in raw mode. Returns true if the
/// pressed letter matches `target` (case-insensitive), false for any other
/// key or non-tty input.
fn confirm_burn(feed: &dyn Fn(), target: char) -> bool {
    let tty = io::stdin().is_terminal();
    if !tty {
        feed();
        return true;
    }
    let orig = raw_on();
    loop {
        if input_ready() {
            match read_byte() {
                Some(b) => {
                    raw_off(&orig);
                    return (b as char).eq_ignore_ascii_case(&target);
                }
                None => break,
            }
        } else {
            feed();
            continue;
        }
    }
    raw_off(&orig);
    false
}

/// Draw a centered warning dialog asking the user to type `target` to confirm
/// the burn. Fills the full background so the dialog reads as a modal overlay.
fn show_dialog(width: usize, height: usize, feed: &dyn Fn(), target: char) {
    let up = target.to_ascii_uppercase();
    let title = " ⚠ 烧毁警告 ";
    let body = " 密钥与档案即将永久销毁 ";
    let prompt1 = format!(" 请输入字母  {}  以确认烧毁，", up);
    let prompt2 = " 按其他任意键返回阅读。";

    let mut inner_w = 6;
    for l in [title, body, &prompt1, prompt2] {
        inner_w = inner_w.max(display_width(l) + 2);
    }
    let box_w = inner_w + 2;
    let box_h = 6;
    let left = width.saturating_sub(box_w) / 2 + 1;
    let top = height.saturating_sub(box_h) / 2 + 1;
    let hline = "═".repeat(box_w - 2);

    // Overlay: only clear the rows the box occupies, leaving the story
    // underneath untouched so a wrong-letter cancel returns cleanly.
    for r in top..=(top + box_h - 1) {
        cursor(r, 1);
        print!("{}{}{}", C_BG_DARK, " ".repeat(width), C_RESET);
    }

    let row = |r: usize, s: &str, color: &str| {
        let sw = display_width(s);
        let pl = (inner_w - sw) / 2;
        let pr = inner_w - sw - pl;
        cursor(r, left);
        print!(
            "{}{}{}{}{}{}{}{}{}",
            C_BG_DARK, color, "║", " ".repeat(pl), s, " ".repeat(pr), "║", C_RESET, C_BG_DARK
        );
    };

    cursor(top, left);
    print!("{}{}{}{}", C_BG_DARK, C_RED, "╔".to_string() + &hline + "╗", C_RESET);
    row(top + 1, title, C_RED);
    row(top + 2, body, C_DIM);

    cursor(top + 3, left);
    let sw = display_width(&prompt1);
    let pl = (inner_w - sw) / 2;
    let pr = inner_w - sw - pl;
    print!("{}{}{}", C_BG_DARK, C_DIM, "║");
    print!("{}", " ".repeat(pl));
    let a = &prompt1[..prompt1.find(up).unwrap()];
    let b = &prompt1[prompt1.find(up).unwrap() + 1..];
    print!("{}{}{}{}{}", a, C_GREEN, up, C_BRIGHT_WHITE, b);
    print!("{}{}{}", " ".repeat(pr), "║", C_RESET);

    row(top + 4, prompt2, C_DIM);
    cursor(top + box_h - 1, left);
    print!("{}{}{}{}", C_BG_DARK, C_RED, "╚".to_string() + &hline + "╝", C_RESET);
    flush();
    feed();
}