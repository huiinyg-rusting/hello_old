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

fn display_width(s: &str) -> usize {
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

pub fn show(lines: &[String], feed: &dyn Fn(), unlock_time: &str) -> usize {
    hide_cursor();
    let width = term_width();
    let height = term_height();
    let mut row = 1;

    let mut rng = Rng::new();

    fill_bg_full(width, height);
    fullscreen_garble(width, height, 20, 100, &mut rng, feed);
    scanline_effect(width, height, &mut rng, feed);

    fill_bg_full(width, height);
    draw_status_bar(width, height, unlock_time);

    let title = "█ TIME GATE █  OPENING THE DOOR  █ TIME GATE █";
    reveal_row_fast(row, title, width, height, unlock_time, &mut rng, feed);
    row += 2;

    draw_hline(row, width, C_CYAN);
    row += 1;

    for line in lines {
        reveal_row_fast(row, line, width, height, unlock_time, &mut rng, feed);
        row += 1;
    }

    draw_hline(row, width, C_CYAN);
    row += 1;

    let foot = "—— 守门人 ——";
    reveal_row_fast(row, foot, width, height, unlock_time, &mut rng, feed);
    row += 1;
    draw_status_bar(width, height, unlock_time);
    sleep(800);
    row
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

fn raw_off(orig: &libc::termios) {
    unsafe {
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, orig);
    }
}

pub fn center_pad(line: &str, width: usize) -> usize {
    let w = display_width(line);
    if w >= width {
        0
    } else {
        (width - w) / 2
    }
}

pub fn wait_for_quit(feed: &dyn Fn()) {
    let tty = io::stdin().is_terminal();
    if !tty {
        return;
    }
    let orig = raw_on();
    loop {
        unsafe {
            let mut pfd = libc::pollfd {
                fd: 0,
                events: libc::POLLIN,
                revents: 0,
            };
            let r = libc::poll(&mut pfd, 1, 100);
            if r > 0 && (pfd.revents & libc::POLLIN) != 0 {
                let mut b = [0u8; 1];
                if io::stdin().read(&mut b).unwrap_or(0) == 0 {
                    break;
                }
                if b[0] == b'q' || b[0] == b'Q' {
                    break;
                }
            } else if r == 0 {
                feed();
                continue;
            } else {
                break;
            }
        }
        feed();
    }
    raw_off(&orig);
    show_cursor();
}