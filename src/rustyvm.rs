const OP_PUSH1: u8 = 0x01;
const OP_PUSH8: u8 = 0x02;
const OP_PUSHKEY: u8 = 0x03;
const OP_DUP: u8 = 0x04;
const OP_SWAP: u8 = 0x05;
const OP_DROP: u8 = 0x06;
const OP_XOR: u8 = 0x07;
const OP_ADD: u8 = 0x08;
const OP_SUB: u8 = 0x09;
const OP_AND: u8 = 0x0A;
const OP_OR: u8 = 0x0B;
const OP_NOT: u8 = 0x0C;
const OP_ROTL: u8 = 0x0D;
const OP_ROTR: u8 = 0x0E;
const OP_WRMEM: u8 = 0x11;
const OP_HALT: u8 = 0x00;

const OP_OPAQUE_PRED_BASE: u8 = 0xE0;
const OP_OPAQUE_PRED_END: u8 = 0xE3;
const OP_CF_OBFUSCATE_BASE: u8 = 0xA0;
const OP_CF_OBFUSCATE_END: u8 = 0xA5;
const OP_OPAQUE_LABEL: u8 = 0xF0;

use std::sync::atomic::{AtomicBool, Ordering};

/// X6: when set, the VM interpreter runs with an extra per-op delay so dynamic
/// analysis under an emulator / hypervisor is noticeably slower. It is
/// informational degradation, never a hard block.
static VM_SLOW: AtomicBool = AtomicBool::new(false);

pub fn set_vm_slow(on: bool) {
    VM_SLOW.store(on, Ordering::SeqCst);
}

fn vm_slow_sleep() {
    if VM_SLOW.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_micros(250));
    }
}

// Side-channel resistant: constant-time conditional select
fn ct_select(cond: bool, a: u64, b: u64) -> u64 {
    let mask = (cond as u64).wrapping_neg();
    (a & mask) | (b & !mask)
}

// Constant-time select for usize values (stack pointer)
fn ct_select_usize(cond: bool, a: usize, b: usize) -> usize {
    ct_select(cond, a as u64, b as u64) as usize
}

// Side-channel resistant: constant-time index access
fn ct_load(material: &[u8], idx: usize) -> u64 {
    let mut result = 0u64;
    for (i, &byte) in material.iter().enumerate() {
        let eq = ((i ^ idx) == 0) as u64;
        let mask = eq.wrapping_neg();
        result ^= (byte as u64) & mask;
    }
    result
}

pub fn run(prog: &[u8], material: &[u8], out: &mut [u8]) -> bool {
    let mut stack: [u64; 16] = [0; 16];
    let mut sp = 0usize;
    let mut ip = 0usize;
    let mut ok = true;

    while ip < prog.len() {
        let op = prog[ip];
        ip += 1;

        let is_push1 = (op == OP_PUSH1) as u64;
        let is_push8 = (op == OP_PUSH8) as u64;
        let is_pushkey = (op == OP_PUSHKEY) as u64;
        let is_dup = (op == OP_DUP) as u64;
        let is_swap = (op == OP_SWAP) as u64;
        let is_drop = (op == OP_DROP) as u64;
        let is_xor = (op == OP_XOR) as u64;
        let is_add = (op == OP_ADD) as u64;
        let is_sub = (op == OP_SUB) as u64;
        let is_and = (op == OP_AND) as u64;
        let is_or = (op == OP_OR) as u64;
        let is_not = (op == OP_NOT) as u64;
        let is_rotl = (op == OP_ROTL) as u64;
        let is_rotr = (op == OP_ROTR) as u64;
        let is_wrmem = (op == OP_WRMEM) as u64;
        let is_halt = (op == OP_HALT) as u64;

        // OP_PUSH1
        if is_push1 == 1 {
            let valid = (ip < prog.len()) as u64;
            let val = if ip < prog.len() { prog[ip] as u64 } else { 0 };
            ip += 1;
            stack[sp] = ct_select(valid != 0, val, stack[sp]);
            sp = ct_select_usize(valid != 0, sp.wrapping_add(1), sp);
            ok &= valid != 0;
        }

        // OP_PUSH8
        if is_push8 == 1 {
            let valid = (ip + 8 <= prog.len()) as u64;
            let mut val = 0u64;
            if valid != 0 {
                val = u64::from_le_bytes(prog[ip..ip + 8].try_into().unwrap());
            }
            ip += 8;
            stack[sp] = ct_select(valid != 0, val, stack[sp]);
            sp = ct_select_usize(valid != 0, sp.wrapping_add(1), sp);
            ok &= valid != 0;
        }

        // OP_PUSHKEY
        if is_pushkey == 1 {
            let idx = if ip < prog.len() { prog[ip] as usize } else { 0 };
            let valid = (ip < prog.len() && idx < material.len()) as u64;
            ip += 1;
            let val = ct_load(material, idx);
            stack[sp] = ct_select(valid != 0, val, stack[sp]);
            sp = ct_select_usize(valid != 0, sp.wrapping_add(1), sp);
            ok &= valid != 0;
        }

        // OP_DUP
        if is_dup == 1 {
            let valid = (sp > 0) as u64;
            let val = stack[sp.wrapping_sub(1)];
            stack[sp] = ct_select(valid != 0, val, stack[sp]);
            sp = ct_select_usize(valid != 0, sp.wrapping_add(1), sp);
            ok &= valid != 0;
        }

        // OP_SWAP
        if is_swap == 1 {
            let valid = (sp >= 2) as u64;
            let a = stack[sp.wrapping_sub(1)];
            let b = stack[sp.wrapping_sub(2)];
            let ca = ct_select(valid != 0, b, a);
            let cb = ct_select(valid != 0, a, b);
            stack[sp.wrapping_sub(1)] = ca;
            stack[sp.wrapping_sub(2)] = cb;
            ok &= valid != 0;
        }

        // OP_DROP
        if is_drop == 1 {
            let valid = (sp > 0) as u64;
            sp = ct_select_usize(valid != 0, sp.wrapping_sub(1), sp);
            ok &= valid != 0;
        }

        // OP_XOR
        if is_xor == 1 {
            let valid = (sp >= 2) as u64;
            let a = stack[sp.wrapping_sub(1)];
            let b = stack[sp.wrapping_sub(2)];
            let res = ct_select(valid != 0, a ^ b, stack[sp.wrapping_sub(1)]);
            sp = ct_select_usize(valid != 0, sp.wrapping_sub(1), sp);
            stack[sp.wrapping_sub(1)] = res;
            ok &= valid != 0;
        }

        // OP_ADD
        if is_add == 1 {
            let valid = (sp >= 2) as u64;
            let a = stack[sp.wrapping_sub(1)];
            let b = stack[sp.wrapping_sub(2)];
            let res = ct_select(valid != 0, a.wrapping_add(b), stack[sp.wrapping_sub(1)]);
            sp = ct_select_usize(valid != 0, sp.wrapping_sub(1), sp);
            stack[sp.wrapping_sub(1)] = res;
            ok &= valid != 0;
        }

        // OP_SUB
        if is_sub == 1 {
            let valid = (sp >= 2) as u64;
            let a = stack[sp.wrapping_sub(1)];
            let b = stack[sp.wrapping_sub(2)];
            let res = ct_select(valid != 0, b.wrapping_sub(a), stack[sp.wrapping_sub(1)]);
            sp = ct_select_usize(valid != 0, sp.wrapping_sub(1), sp);
            stack[sp.wrapping_sub(1)] = res;
            ok &= valid != 0;
        }

        // OP_AND
        if is_and == 1 {
            let valid = (sp >= 2) as u64;
            let a = stack[sp.wrapping_sub(1)];
            let b = stack[sp.wrapping_sub(2)];
            let res = ct_select(valid != 0, a & b, stack[sp.wrapping_sub(1)]);
            sp = ct_select_usize(valid != 0, sp.wrapping_sub(1), sp);
            stack[sp.wrapping_sub(1)] = res;
            ok &= valid != 0;
        }

        // OP_OR
        if is_or == 1 {
            let valid = (sp >= 2) as u64;
            let a = stack[sp.wrapping_sub(1)];
            let b = stack[sp.wrapping_sub(2)];
            let res = ct_select(valid != 0, a | b, stack[sp.wrapping_sub(1)]);
            sp = ct_select_usize(valid != 0, sp.wrapping_sub(1), sp);
            stack[sp.wrapping_sub(1)] = res;
            ok &= valid != 0;
        }

        // OP_NOT
        if is_not == 1 {
            let valid = (sp > 0) as u64;
            let a = stack[sp.wrapping_sub(1)];
            let res = ct_select(valid != 0, !a, a);
            stack[sp.wrapping_sub(1)] = res;
            ok &= valid != 0;
        }

        // OP_ROTL
        if is_rotl == 1 {
            let valid = (ip < prog.len() && sp > 0) as u64;
            let n = if ip < prog.len() { (prog[ip] as u32) & 63 } else { 0 };
            ip += 1;
            let a = stack[sp.wrapping_sub(1)];
            let res = ct_select(valid != 0, a.rotate_left(n), a);
            stack[sp.wrapping_sub(1)] = res;
            ok &= valid != 0;
        }

        // OP_ROTR
        if is_rotr == 1 {
            let valid = (ip < prog.len() && sp > 0) as u64;
            let n = if ip < prog.len() { (prog[ip] as u32) & 63 } else { 0 };
            ip += 1;
            let a = stack[sp.wrapping_sub(1)];
            let res = ct_select(valid != 0, a.rotate_right(n), a);
            stack[sp.wrapping_sub(1)] = res;
            ok &= valid != 0;
        }

        // OP_WRMEM - constant-time output write
        if is_wrmem == 1 {
            let valid_idx = (ip < prog.len()) as u64;
            let idx = if ip < prog.len() { prog[ip] as usize } else { 0 };
            ip += 1;
            let valid_sp = (sp > 0) as u64;
            let val = if sp > 0 { stack[sp.wrapping_sub(1)] } else { 0 };
            let valid_out = (idx < out.len()) as u64;
            let valid = valid_idx & valid_sp & valid_out;
            for (i, byte) in out.iter_mut().enumerate() {
                let eq = ((i ^ idx) == 0) as u64;
                let mask = eq.wrapping_neg() & ((valid != 0) as u64).wrapping_neg();
                *byte ^= ((val as u8) ^ *byte) & (mask as u8);
            }
            sp = ct_select_usize(valid_sp != 0, sp.wrapping_sub(1), sp);
            ok &= valid != 0;
        }

        // OP_OPAQUE_LABEL
        if op == OP_OPAQUE_LABEL {
            let valid = (ip + 2 <= prog.len()) as u64;
            ip += 2;
            ok &= valid != 0;
        }

        // OP_HALT
        if is_halt == 1 {
            break;
        }

        // Opaque predicates (0xE0-0xE3) - constant-time skip
        let is_ppred = (op >= OP_OPAQUE_PRED_BASE && op <= OP_OPAQUE_PRED_END) as u64;
        if is_ppred == 1 {
            let valid = (ip < prog.len()) as u64;
            ip += 1;
            ok &= valid != 0;
        }

        // CF obfuscation (0xA0-0xA5) - constant-time skip
        let is_cf = (op >= OP_CF_OBFUSCATE_BASE && op <= OP_CF_OBFUSCATE_END) as u64;
        if is_cf == 1 {
            let valid = (ip + 2 <= prog.len()) as u64;
            ip += 2;
            ok &= valid != 0;
        }

        // Unknown opcode
        let known = op == OP_PUSH1
            || op == OP_PUSH8
            || op == OP_PUSHKEY
            || op == OP_DUP
            || op == OP_SWAP
            || op == OP_DROP
            || op == OP_XOR
            || op == OP_ADD
            || op == OP_SUB
            || op == OP_AND
            || op == OP_OR
            || op == OP_NOT
            || op == OP_ROTL
            || op == OP_ROTR
            || op == OP_WRMEM
            || op == OP_OPAQUE_LABEL
            || op == OP_HALT
            || (op >= OP_OPAQUE_PRED_BASE && op <= OP_OPAQUE_PRED_END)
            || (op >= OP_CF_OBFUSCATE_BASE && op <= OP_CF_OBFUSCATE_END);
        ok &= known;

        // Stack overflow check
        let overflow = (sp >= 16) as u64;
        ok &= overflow == 0;

        // X6: VM degradation — extra delay per instruction under a hypervisor.
        vm_slow_sleep();
    }

    ok
}