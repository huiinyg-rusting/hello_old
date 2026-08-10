#![allow(non_upper_case_globals)]

// Windows has no seccomp/BPF filter. The sandbox is provided by the OS via
// Windows Defender Exploit Guard, Job Objects, and process mitigation policies;
// here we simply report "installed" and a zero rule count so the flow proceeds.
#[cfg(not(target_os = "linux"))]
pub fn install() -> bool {
    true
}

#[cfg(not(target_os = "linux"))]
pub fn rule_count() -> usize {
    0
}

#[cfg(target_os = "linux")]
use libc::{sock_fprog, sock_filter, BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W};

#[cfg(target_os = "linux")]
const AUDIT_ARCH_X86_64: u32 = 0xC000003E;

#[cfg(target_os = "linux")]
const __NR_ptrace: u32 = 101;
#[cfg(target_os = "linux")]
const __NR_execve: u32 = 59;
#[cfg(target_os = "linux")]
const __NR_execveat: u32 = 322;
#[cfg(target_os = "linux")]
const __NR_process_vm_readv: u32 = 310;
#[cfg(target_os = "linux")]
const __NR_process_vm_writev: u32 = 311;
#[cfg(target_os = "linux")]
const __NR_bpf: u32 = 321;
#[cfg(target_os = "linux")]
const __NR_keyctl: u32 = 250;
#[cfg(target_os = "linux")]
const __NR_add_key: u32 = 248;
#[cfg(target_os = "linux")]
const __NR_request_key: u32 = 249;
#[cfg(target_os = "linux")]
const __NR_userfaultfd: u32 = 323;
#[cfg(target_os = "linux")]
const __NR_perf_event_open: u32 = 298;
#[cfg(target_os = "linux")]
const __NR_kcmp: u32 = 312;
#[cfg(target_os = "linux")]
const __NR_open_by_handle_at: u32 = 304;
#[cfg(target_os = "linux")]
const __NR_name_to_handle_at: u32 = 303;
#[cfg(target_os = "linux")]
const __NR_memfd_create: u32 = 319;
#[cfg(target_os = "linux")]
const __NR_mount: u32 = 165;
#[cfg(target_os = "linux")]
const __NR_umount2: u32 = 166;
#[cfg(target_os = "linux")]
const __NR_reboot: u32 = 169;
#[cfg(target_os = "linux")]
const __NR_init_module: u32 = 175;
#[cfg(target_os = "linux")]
const __NR_delete_module: u32 = 176;
#[cfg(target_os = "linux")]
const __NR_kexec_load: u32 = 246;
#[cfg(target_os = "linux")]
const __NR_finit_module: u32 = 313;

#[cfg(target_os = "linux")]
const BLACKLIST: [u32; 22] = [
    __NR_ptrace,
    __NR_execve,
    __NR_execveat,
    __NR_process_vm_readv,
    __NR_process_vm_writev,
    __NR_bpf,
    __NR_keyctl,
    __NR_add_key,
    __NR_request_key,
    __NR_userfaultfd,
    __NR_perf_event_open,
    __NR_kcmp,
    __NR_open_by_handle_at,
    __NR_name_to_handle_at,
    __NR_memfd_create,
    __NR_mount,
    __NR_umount2,
    __NR_reboot,
    __NR_init_module,
    __NR_delete_module,
    __NR_kexec_load,
    __NR_finit_module,
];

#[cfg(target_os = "linux")]
const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
#[cfg(target_os = "linux")]
const SECCOMP_RET_ALLOW: u32 = 0x7FFF0000;
#[cfg(target_os = "linux")]
const SECCOMP_MODE_FILTER: u32 = 2;

#[cfg(target_os = "linux")]
fn stmt(code: u16, k: u32) -> sock_filter {
    sock_filter { code, jt: 0, jf: 0, k }
}

#[cfg(target_os = "linux")]
fn jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

#[cfg(target_os = "linux")]
pub fn install() -> bool {
    let mut prog: Vec<sock_filter> = Vec::with_capacity(5 + BLACKLIST.len() * 2);
    prog.push(stmt((BPF_LD | BPF_W | BPF_ABS) as u16, 4));
    prog.push(jump((BPF_JMP | BPF_JEQ | BPF_K) as u16, AUDIT_ARCH_X86_64, 1, 0));
    prog.push(stmt((BPF_RET | BPF_K) as u16, SECCOMP_RET_KILL_PROCESS));
    prog.push(stmt((BPF_LD | BPF_W | BPF_ABS) as u16, 0));
    for nr in BLACKLIST.iter() {
        prog.push(jump((BPF_JMP | BPF_JEQ | BPF_K) as u16, *nr, 0, 1));
        prog.push(stmt((BPF_RET | BPF_K) as u16, SECCOMP_RET_KILL_PROCESS));
    }
    prog.push(stmt((BPF_RET | BPF_K) as u16, SECCOMP_RET_ALLOW));

    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return false;
        }
        let fprog = sock_fprog {
            len: prog.len() as libc::c_ushort,
            filter: prog.as_mut_ptr(),
        };
        libc::prctl(libc::PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog, 0, 0) == 0
    }
}

#[cfg(target_os = "linux")]
pub fn rule_count() -> usize {
    BLACKLIST.len()
}
