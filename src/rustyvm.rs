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

pub fn run(prog: &[u8], material: &[u8], out: &mut [u8]) -> bool {
    let mut stack: Vec<u64> = Vec::with_capacity(16);
    let mut ip = 0usize;
    while ip < prog.len() {
        let op = prog[ip];
        ip += 1;
        match op {
            OP_PUSH1 => {
                if ip >= prog.len() { return false; }
                stack.push(prog[ip] as u64);
                ip += 1;
            }
            OP_PUSH8 => {
                if ip + 8 > prog.len() { return false; }
                let v = u64::from_le_bytes(prog[ip..ip + 8].try_into().unwrap());
                stack.push(v);
                ip += 8;
            }
            OP_PUSHKEY => {
                if ip >= prog.len() { return false; }
                let idx = prog[ip] as usize;
                ip += 1;
                if idx >= material.len() {
                    return false;
                }
                stack.push(material[idx] as u64);
            }
            OP_DUP => {
                let a = *stack.last().unwrap_or(&0);
                stack.push(a);
            }
            OP_SWAP => {
                if stack.len() < 2 { return false; }
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                stack.push(a);
                stack.push(b);
            }
            OP_DROP => {
                if stack.is_empty() { return false; }
                stack.pop();
            }
            OP_XOR => {
                if stack.len() < 2 { return false; }
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                stack.push(a ^ b);
            }
            OP_ADD => {
                if stack.len() < 2 { return false; }
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                stack.push(a.wrapping_add(b));
            }
            OP_SUB => {
                if stack.len() < 2 { return false; }
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                stack.push(b.wrapping_sub(a));
            }
            OP_AND => {
                if stack.len() < 2 { return false; }
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                stack.push(a & b);
            }
            OP_OR => {
                if stack.len() < 2 { return false; }
                let a = stack.pop().unwrap();
                let b = stack.pop().unwrap();
                stack.push(a | b);
            }
            OP_NOT => {
                if stack.is_empty() { return false; }
                let a = stack.pop().unwrap();
                stack.push(!a);
            }
            OP_ROTL => {
                if ip >= prog.len() { return false; }
                let n = (prog[ip] as u32) & 63;
                ip += 1;
                if stack.is_empty() { return false; }
                let a = stack.pop().unwrap();
                stack.push(a.rotate_left(n));
            }
            OP_ROTR => {
                if ip >= prog.len() { return false; }
                let n = (prog[ip] as u32) & 63;
                ip += 1;
                if stack.is_empty() { return false; }
                let a = stack.pop().unwrap();
                stack.push(a.rotate_right(n));
            }
            OP_WRMEM => {
                if ip >= prog.len() { return false; }
                let idx = prog[ip] as usize;
                ip += 1;
                if idx >= out.len() { return false; }
                if stack.is_empty() { return false; }
                let v = stack.pop().unwrap();
                out[idx] = v as u8;
            }
            OP_OPAQUE_LABEL => {
                if ip + 2 > prog.len() { return false; }
                ip += 2;
            }
            OP_HALT => break,
            op if op >= OP_OPAQUE_PRED_BASE && op <= OP_OPAQUE_PRED_END => {
                if ip >= prog.len() { return false; }
                ip += 1;
            }
            op if op >= OP_CF_OBFUSCATE_BASE && op <= OP_CF_OBFUSCATE_END => {
                if ip + 2 > prog.len() { return false; }
                ip += 2;
            }
            _ => return false,
        }
        if stack.len() > 256 {
            return false;
        }
    }
    true
}