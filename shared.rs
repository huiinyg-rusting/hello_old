#[allow(dead_code)]
pub const PASSWORD: &[u8] = b"114514";
pub const KEY_LEN: usize = 64;
pub const OPEN_TIMESTAMP_UNIX_SECONDS: u64 = 1_755_000_000;
pub const NTP_SERVERS: [&str; 5] = [
    "ntp.aliyun.com",
    "ntp.myhuaweicloud.com",
    "time.cloudflare.com",
    "time.windows.com",
    "ntp.ntsc.ac.cn",
];
pub const CLOCK_DRIFT_LIMIT_SECONDS: f64 = 10.0;
