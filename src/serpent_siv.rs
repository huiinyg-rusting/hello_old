// Serpent-256-SIV: SIV (RFC 5297) authenticated encryption built on the
/// Serpent block cipher. The 256-bit master key is split into two 128-bit
/// subkeys K1 (CMAC / S2V) and K2 (CTR), matching the AEAD_AES_SIV_CMAC_256
/// construction but with Serpent in place of AES.
///
/// This module is flat (only external-crate imports) so it can be shared
/// verbatim between the build script (`build.rs`) and the runtime via `include!`.

use cmac::{Cmac, Mac};
use cipher::{Block, BlockCipherEncrypt, KeyInit};
use serpent::Serpent;

const B: usize = 16;

type CmacSerpent = Cmac<Serpent>;
type Block16 = Block<Serpent>;

fn xor_block(a: &[u8; B], b: &[u8; B]) -> [u8; B] {
    let mut o = [0u8; B];
    let mut i = 0;
    while i < B {
        o[i] = a[i] ^ b[i];
        i += 1;
    }
    o
}

// Finite-field doubling over GF(2^128) with the AES polynomial
// x^128 + x^7 + x^2 + x + 1. The 128-bit value is stored LSB-first
// (byte 0 = bits 0..7, byte 15 = bits 120..127; bit 127 is byte[15]'s MSB).
fn dbl(s: &mut [u8; B]) {
    let msb = s[B - 1] >> 7;
    let mut i = B - 1;
    while i > 0 {
        s[i] = (s[i] << 1) | (s[i - 1] >> 7);
        i -= 1;
    }
    s[0] <<= 1;
    if msb == 1 {
        s[0] ^= 0x87;
    }
}

fn serpent_enc_block(k: &[u8], in16: &[u8; B]) -> [u8; B] {
    let cipher = Serpent::new_from_slice(k).expect("serpent key length");
    let mut blk = Block16::from_slice(in16).clone();
    cipher.encrypt_block(&mut blk);
    let mut out = [0u8; B];
    out.copy_from_slice(blk.as_slice());
    out
}

fn cmac_serpent(key: &[u8], data: &[u8]) -> [u8; B] {
    let mut mac = <CmacSerpent as cmac::KeyInit>::new_from_slice(key).expect("cmac key length");
    mac.update(data);
    let tag = mac.finalize();
    let mut out = [0u8; B];
    out.copy_from_slice(tag.as_bytes());
    out
}

// 10* padding (pad16): append 0x80 then zeros to reach 16 bytes. Input < 16 bytes.
fn pad16(x: &[u8]) -> [u8; B] {
    debug_assert!(x.len() < B);
    let mut b = [0u8; B];
    b[..x.len()].copy_from_slice(x);
    b[x.len()] |= 0x80;
    b
}

// S2V_K(ad..., last) returning a 16-byte synthetic IV.
fn s2v(k1: &[u8], ads: &[&[u8]], last: &[u8]) -> [u8; B] {
    let zero = [0u8; B];
    let mut d = cmac_serpent(k1, &zero);
    for a in ads {
        let c = cmac_serpent(k1, a);
        d = xor_block(&d, &c);
        dbl(&mut d);
    }
    // Finalize with the last element (the plaintext).
    let v = if last.len() >= B {
        // T = last xorend d  (xor d onto the final 16 bytes of last)
        let mut t = last.to_vec();
        let end = t.len() - B;
        let mut j = 0;
        while j < B {
            t[end + j] ^= d[j];
            j += 1;
        }
        cmac_serpent(k1, &t)
    } else {
        // T = dbl(d) ||xor pad(last)
        let mut t = dbl2(&d);
        let p = pad16(last);
        t = xor_block(&t, &p);
        cmac_serpent(k1, &t)
    };
    v
}

fn dbl2(s: &[u8; B]) -> [u8; B] {
    let mut t = *s;
    dbl(&mut t);
    t
}

// Increment a 128-bit little-endian-byte counter in place.
fn inc128(c: &mut [u8; B]) {
    let mut i = 0;
    while i < B {
        let (v, carry) = c[i].overflowing_add(1);
        c[i] = v;
        if !carry {
            return;
        }
        i += 1;
    }
}

// Zero the CTR-optimization bits (bit 31 and bit 63) of the synthetic IV.
fn ctr_mask(v: &mut [u8; B]) {
    v[3] &= 0x7f;
    v[7] &= 0x7f;
}

pub fn siv_encrypt(key32: &[u8], ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let k1 = &key32[..16];
    let k2 = &key32[16..32];
    let mut v = s2v(k1, &[ad], plaintext);
    let mut q = v;
    ctr_mask(&mut q);
    let mut counter = q;
    let mut out: Vec<u8> = Vec::with_capacity(B + plaintext.len());
    out.extend_from_slice(&v);
    let mut i = 0;
    while i < plaintext.len() {
        let ek = serpent_enc_block(k2, &counter);
        let mut j = 0;
        let take = (B).min(plaintext.len() - i);
        while j < take {
            out.push(plaintext[i + j] ^ ek[j]);
            j += 1;
        }
        inc128(&mut counter);
        i += take;
    }
    out
}

pub fn siv_decrypt(key32: &[u8], ad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < B {
        return None;
    }
    let k1 = &key32[..16];
    let k2 = &key32[16..32];
    let mut v = [0u8; B];
    v.copy_from_slice(&ciphertext[..B]);
    let ct = &ciphertext[B..];
    let mut q = v;
    ctr_mask(&mut q);
    let mut counter = q;
    let mut out: Vec<u8> = Vec::with_capacity(ct.len());
    let mut i = 0;
    while i < ct.len() {
        let ek = serpent_enc_block(k2, &counter);
        let mut j = 0;
        let take = (B).min(ct.len() - i);
        while j < take {
            out.push(ct[i + j] ^ ek[j]);
            j += 1;
        }
        inc128(&mut counter);
        i += take;
    }
    let v_check = s2v(k1, &[ad], &out);
    if v_check != v {
        return None;
    }
    Some(out)
}


