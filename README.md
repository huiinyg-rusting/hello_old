# hello_old — Time-Gated Decryption Binary

A hardened Rust binary that embeds a secret text file and only reveals it after a configured Unix timestamp, after passing multiple runtime integrity checks. The binary is statically linked for x86_64 Linux and can be copied to any compatible machine and run directly. After the content is displayed, the binary deletes itself ("burn after reading").

## Features

### Time Gate
- The embedded text is encrypted and only decrypted after `OPEN_TIMESTAMP_UNIX_SECONDS` (default: 2025-08-12 12:00:00 UTC).
- If the local clock is before the gate, the binary refuses with a clear message and exits.
- The remaining time until opening is displayed when the gate has not yet arrived.

### Dual-Layer ChaCha20-Poly1305 Encryption
- At build time, two independent 32-byte keys (K1, K2) are generated randomly.
- The timestamp is encrypted with K1; the payload is double-encrypted (outer K1, inner K2).
- At runtime, a custom 64-instruction VM (`RustyVM`) reconstructs both keys from a shared 64-byte material (`km.bin`) using XOR masks — the keys never exist as a contiguous blob in the binary.

### RustyVM (Custom Virtual Machine)
- A minimal stack-based VM defined in `src/rustyvm.rs`.
- 16 opcodes: `PUSH1`, `PUSH8`, `PUSHKEY`, `DUP`, `SWAP`, `DROP`, `XOR`, `ADD`, `SUB`, `AND`, `OR`, `NOT`, `ROTL`, `ROTR`, `WRMEM`, `HALT`.
- The VM program is itself encrypted at build time and decrypted at runtime using a bootstrap key derived from the password.

### Runtime Password
- The binary prompts for a password at runtime with asterisk feedback (`*` characters).
- The password is never embedded in the binary.
- Build-time password is defined as `pub const PASSWORD` in `shared.rs` (default: `OpenThePodBayDoors_HAL9000_1968`).

### NTP Time Verification
- Concurrently queries 5 public NTP servers (`ntp.aliyun.com`, `ntp.myhuaweicloud.com`, `time.cloudflare.com`, `time.windows.com`, `ntp.ntsc.ac.cn`).
- Takes the median of servers within a 10-second drift tolerance.
- If all public NTP servers fail, prompts the user to enter a custom NTP server address.
- Compares NTP time against the local clock and rejects if drift exceeds the limit.

### Clock Manipulation Detection
- Monitors the relationship between `CLOCK_MONOTONIC` and `CLOCK_REALTIME`.
- If the wall clock jumps by more than 2 seconds relative to monotonic time, the binary self-destructs.

### Watchdog Self-Destruct
- A background thread checks every 400ms:
  - **Stale heartbeat**: if the main thread hasn't updated the heartbeat for 6 seconds, SIGKILL.
  - **Tracer detection**: if `/proc/self/status` shows a non-zero `TracerPid`, SIGKILL.
  - **Key hash mismatch**: if the key material in memory has been tampered with, SIGKILL.
  - **Binary tampering**: if `/proc/self/exe` hash changes from the baseline, SIGKILL.

### Seccomp Blacklist
- Installs a BPF-based seccomp filter that blocks 22 dangerous syscalls:
  `ptrace`, `execve`, `execveat`, `process_vm_readv`, `process_vm_writev`, `bpf`, `keyctl`, `add_key`, `request_key`, `userfaultfd`, `perf_event_open`, `kcmp`, `open_by_handle_at`, `name_to_handle_at`, `memfd_create`, `mount`, `umount2`, `reboot`, `init_module`, `delete_module`, `kexec_load`, `finit_module`.

### Memory Hardening
- Key material and decrypted content are locked into RAM with `mlock()` and placed on guard pages (`PROT_NONE` at both ends).
- After the text is displayed, both buffers are set to `PROT_NONE` before the burn animation.
- On drop, all sensitive buffers are zeroized with `write_volatile` and a memory fence.
- The binary deletes itself from disk after the burn animation ("burn after reading").

### Signal Immunity
- `SIGINT`, `SIGTERM`, `SIGHUP`, `SIGQUIT`, `SIGTSTP`, and `SIGPIPE` are all set to `SIG_IGN`.
- Only `SIGKILL` (from the watchdog) can terminate the process.

### Anti-Debug / Anti-Tamper
- `PR_SET_DUMPABLE` is disabled (prevents core dumps).
- `PR_SET_PTRACER` is set to 0 (prevents ptrace attachment).
- `/proc/self/maps` is scanned for `LD_PRELOAD` and `LD_LIBRARY_PATH` injection.
- RWX (writable + executable) memory regions are detected and trigger self-destruction.

### TUI (Terminal User Interface)
- Garbled text animation reveals the content character by character.
- After reveal, the user can press `q` to trigger the burn animation and exit.
- On EOF (piped input), the burn animation plays automatically.
- After the burn animation, the binary deletes itself from disk.

## Build

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

The binary is at `target/x86_64-unknown-linux-musl/release/hello_old`.

### Build-time Password
- The password is defined as `pub const PASSWORD` in `shared.rs`.
- The build script uses this constant directly — no TTY interaction needed.
- To change the password, edit `shared.rs` and rebuild.

### Random SALT
- A 16-byte random SALT is generated at build time and embedded in the binary via `OUT_DIR/salt.bin`.
- Each build produces a different SALT, ensuring different encryption keys even with the same password.

## Usage

```bash
# Copy the binary to any x86_64 Linux machine and run it
./hello_old
# Enter the password when prompted (asterisks shown)
# After viewing, press q to burn and exit — the binary deletes itself
```

Or pipe the password (for automation):

```bash
printf '%s\n' 'OpenThePodBayDoors_HAL9000_1968' | ./hello_old
```

## Requirements

- Linux x86_64
- No dependencies (fully static binary)
- Kernel with seccomp support (all modern Linux kernels)

## Security Notes

- The binary is statically linked and stripped, making it portable across x86_64 Linux distributions.
- The password is not stored in the binary; it must be entered at runtime with asterisk feedback.
- All cryptographic keys are derived at runtime and never stored on disk.
- The binary deletes itself after displaying the content (burn after reading).
- The watchdog thread will SIGKILL the process if any integrity check fails.