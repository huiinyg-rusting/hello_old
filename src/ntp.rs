use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;
const NTP_FRAC_SCALE: f64 = 4_294_967_296.0;

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

pub fn unix_now_u64() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u64
}

pub fn query(host: &str) -> Option<(f64, f64)> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    let addr = format!("{host}:123").to_socket_addrs().ok()?.next()?;

    let t1 = unix_now();
    let mut pkt = [0u8; 48];
    pkt[0] = 0x1B;
    let t1_ntp = (t1 as u64).wrapping_add(NTP_EPOCH_OFFSET);
    pkt[24..32].copy_from_slice(&t1_ntp.to_be_bytes());
    sock.send_to(&pkt, addr).ok()?;

    let mut buf = [0u8; 48];
    let n = sock.recv(&mut buf).ok()?;
    if n < 48 {
        return None;
    }
    let t2 = unix_now();

    let secs = u32::from_be_bytes(buf[40..44].try_into().ok()?) as u64;
    let frac = u32::from_be_bytes(buf[44..48].try_into().ok()?) as f64 / NTP_FRAC_SCALE;
    let tx = secs as f64 - NTP_EPOCH_OFFSET as f64 + frac;
    let half_rtt = (t2 - t1) * 0.5;
    let server_now = tx + half_rtt;
    let drift = server_now - t2;
    Some((server_now, drift))
}

pub fn sync_all(hosts: &[&str]) -> Vec<(String, f64, f64)> {
    let results: Arc<Mutex<Vec<(String, f64, f64)>>> = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    for host in hosts {
        let host = host.to_string();
        let r = Arc::clone(&results);
        handles.push(std::thread::spawn(move || {
            if let Some((n, d)) = query(&host) {
                r.lock().unwrap().push((host, n, d));
            }
        }));
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let done = handles.iter().all(|h| h.is_finished());
        if done || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    for h in handles {
        drop(h);
    }
    results.lock().map(|g| g.clone()).unwrap_or_default()
}
