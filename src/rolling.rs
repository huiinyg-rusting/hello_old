use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Rolling in-memory cipher for the decrypted content while it sits in the
/// secure buffer. A per-process random 256-byte mask is XORed over the bytes;
/// the mask is replaced on every watchdog tick so a memory dump taken at any
/// moment sees ciphertext under a mask that has already been rotated. The
/// plaintext is only exposed during the brief decrypt for display, and the
/// mask is wiped on drop / disarm.
static ARMED: AtomicBool = AtomicBool::new(false);
static PTR: Mutex<usize> = Mutex::new(0);
static LEN: Mutex<usize> = Mutex::new(0);
static MASK: Mutex<[u8; 256]> = Mutex::new([0u8; 256]);

fn fill_mask(m: &mut [u8; 256]) {
    if getrandom::getrandom(m).is_err() {
        let mut x = 0x9e3779b97f4a7c15u64;
        for b in m.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
    }
}

/// Encrypt `ptr[..len]` in place and arm the rolling cipher.
pub fn arm(ptr: *mut u8, len: usize) {
    if len == 0 {
        return;
    }
    {
        let mut m = MASK.lock().unwrap();
        fill_mask(&mut m);
    }
    unsafe {
        let s = std::slice::from_raw_parts_mut(ptr, len);
        let m = MASK.lock().unwrap();
        for i in 0..len {
            s[i] ^= m[i & 0xff];
        }
    }
    *PTR.lock().unwrap() = ptr as usize;
    *LEN.lock().unwrap() = len;
    ARMED.store(true, Ordering::SeqCst);
}

/// Called periodically (watchdog tick): replace the mask, re-encrypting in
/// place by XORing the delta. The buffer stays ciphertext at all times; only
/// the mask changes.
pub fn rotate() {
    if !ARMED.load(Ordering::SeqCst) {
        return;
    }
    let ptr = *PTR.lock().unwrap();
    let len = *LEN.lock().unwrap();
    let mut m = MASK.lock().unwrap();
    let mut nm = [0u8; 256];
    fill_mask(&mut nm);
    unsafe {
        let s = std::slice::from_raw_parts_mut(ptr as *mut u8, len);
        for i in 0..len {
            s[i] ^= m[i & 0xff] ^ nm[i & 0xff];
        }
    }
    *m = nm;
    std::sync::atomic::fence(Ordering::SeqCst);
}

/// Decrypt back to plaintext and disarm. Also wipes the mask so no stale key
/// survives after the content has been consumed.
pub fn disarm() {
    if !ARMED.load(Ordering::SeqCst) {
        return;
    }
    let ptr = *PTR.lock().unwrap();
    let len = *LEN.lock().unwrap();
    unsafe {
        let s = std::slice::from_raw_parts_mut(ptr as *mut u8, len);
        let m = MASK.lock().unwrap();
        for i in 0..len {
            s[i] ^= m[i & 0xff];
        }
    }
    let mut m = MASK.lock().unwrap();
    for b in m.iter_mut() {
        *b = 0;
    }
    ARMED.store(false, Ordering::SeqCst);
}
