# hello_old — The Keeper of the Time Gate

AI made

If a secret were a city, `hello_old` would be its **Great Wall of Time**.

It is not an ordinary key. It is a **castle of seven nested gates, each latched with a different lock**. An intruder must break through every single gate in order; the moment any gate senses the slightest disturbance, the entire castle **sets itself on fire**, reducing the secret inside to ash — not a single page survives.

How stubborn is it? It **trusts no motherboard battery**. Clocks decay, cells drain, and on some machine decades from now you cannot even predict the year. So it hands the verdict to many "star clocks" scattered across the network (NTP servers): only when they align with one another *and* with the reading on your own watch does it turn the first hinge. You can drop it into a pocket and carry it to any x86_64 machine years from now. It does not care about its host — only about time and the passphrase.

Its purpose is simple and solemn: **seal a text away until a chosen moment, then deliver it** — a will, a key backup, a message travelling across decades. It is an envelope that tears open only when the hour strikes.

Recommended usage:

1. Copy `hello_old` to the target machine and run it.
2. Before the hour: it will coldly tell you "the door is locked".
3. At the hour: enter the passphrase; it releases the text character by character, with ceremonial pacing.
4. Press `q` when done — it deletes itself. **Read once, burn forever.**

> Put your most precious thing inside, then close the door in peace. It chews up the key and the lock together.

---



### The Full Pipeline: 11 Algorithms Stacked, 7 Crypto Layers + Runtime Defense

Decryption is not a single step but a chain that must be breached layer by layer — where any single failure triggers self-destruction:

```
passphrase
 │  Argon2id (256 MiB, 4 iters, 8 lanes)
 ▼
master key → RustyVM custom VM (16 opcodes, constant-time execution)
 │  reconstructs k1∥k2 from encrypted km.bin
 ▼
6 HKDF-SHA256 wrapping keys
  ├─► RSA-4096-OAEP private-key decrypt ──► shard1
  ├─► Kyber-1024 (ML-KEM) decapsulate ─────► shard2
  ├─► Classic McEliece-6960119f decapsulate► shard3
  ├─► FrodoKEM-1344 decapsulate ──────────► shard4
  ├─► Dilithium-5 (ML-DSA-87) verify ──────► shard5 = blake3(pubkey)
  ├─► SM3-256 (Chinese national hash) ────► shard6 = sm3(pubkey)
  └─► Serpent-256-SIV unwrap DEK ─────────► DEK
  │
  ▼
  six shards XOR-combined into the 32-byte Data Encryption Key (DEK) ①
  ▼
  Ed448 + Dilithium-5 dual signature verify (ts∥DEK∥payload-hash)
  ▼
  Serpent-256-SIV decrypt payload
    └─► de-whiten with k1∥k2∥SALT keystream
    └─► LZMA inflate back to [meta_len][meta_json][text]
    └─► plaintext lands directly in a locked+guard-paged buffer, never a heap Vec
  ```

  ① `RSA ⊕ Kyber ⊕ McEliece ⊕ FrodoKEM ⊕ SHA3-256(Dilithium VK) ⊕ SM3-256(Dilithium VK)`
  → 256-bit DEK. The last two shards hash the *same* Dilithium public key with two independent
  primitives (BLAKE3 + SM3); defeating one hash still leaves the other, so DEK recombination fails.
  The payload is LZMA-compressed, then byte-XOR-whitened with a blake3 keystream derived from
  `k1∥k2∥SALT`, and only then sealed with Serpent-SIV — possessing the DEK alone is still not
  enough; the password-derived keys are required to recover the plaintext.

**An attacker must simultaneously defeat:**

| Dimension | Strength |
|---|---|
| Key derivation | Argon2id: 256 MiB memory-hard, 4 iterations, 8 lanes — brute force is expensive |
| Post-quantum KEM ×4 | RSA-4096-OAEP + Kyber-1024 + McEliece-6960119f + FrodoKEM-1344 — miss one and DEK recombination fails |
| Signatures ×2 | Ed448 + CRYSTALS-Dilithium-5 (ML-DSA-87) — tamper and it self-destructs |
| Symmetric cipher | Serpent-256-SIV: authenticated encryption with a strong security proof |
| Custom VM | 16-opcode RustyVM; the key never exists as contiguous plaintext |
| Time gate | Local clock must align with multiple NTP servers within ±10 s, or access is refused |
| Runtime defense | seccomp-BPF, mlock + guard pages, watchdog, TracerPid, LD_PRELOAD/RWX checks, read-then-burn |

### Side-Channel Hardening

- **Full constant-time**: all secret comparisons (`ct_eq`), conditional moves, and indexed accesses use the `subtle` crate — no secret-dependent branches.
- **Fixed-step decryption**: the wrong-passphrase path runs the same volume of dummy `burn_cycles` work (~8M rounds of dependency-chained arithmetic) as the real derivation — success and failure are timing-indistinguishable.
- **Cache-timing defense**: keys and payload are evicted cache-line by cache-line with `clflush` (`flush_mem`) immediately after use.
- **Burn after reading**: buffers are zeroized with a memory fence, unmapped, and the binary deletes itself on exit.

### Time Gating (Built for the Future)

- The unlock timestamp is embedded at build time, doubly encrypted, and verified at runtime with constant-time comparison (`ct_eq`).
- The verdict relies **only on NTP consensus** (median of 5 servers, ±10 s tolerance); the local clock is a loose reference — no motherboard RTC / BIOS clock is trusted.
- A monotonic-clock anchor detects wall-clock jumps to prevent rollback.

### Build

```bash
cargo build --release --target x86_64-unknown-linux-musl
# artifact: target/x86_64-unknown-linux-musl/release/hello_old
```

- Generic x86-64 instruction set (`target-cpu=x86-64`): runs on any x86_64 Linux box, not bound to the build machine's CPU features.
- Fully static, zero runtime dependencies.
- Passphrase lives in `shared.rs` (default `114514`); SALT is randomly regenerated each build.

### Configuration (tune 4 things to fully customize)

Every tunable setting lives in two files: `shared.rs` (passphrase, time, NTP) and `read.txt` (the secret to seal). Re-run `cargo build` after editing.

| Setting | Location | Description |
|---|---|---|
| Passphrase | `shared.rs` → `PASSWORD` | Unlock passphrase; edit and rebuild — never leak it |
| Unlock time | `shared.rs` → `OPEN_TIMESTAMP_UNIX_SECONDS` | Unix seconds; content is withheld until this moment |
| Secret text | `read.txt` | The content embedded and encrypted at build time |
| NTP servers | `shared.rs` → `NTP_SERVERS` | Time-consensus sources; swap in servers you trust |
| Clock tolerance | `shared.rs` → `CLOCK_DRIFT_LIMIT_SECONDS` | Max allowed local-vs-NTP drift (default 10 s) |

**How to compute the unlock time?** Use any Unix timestamp tool:

```bash
date -d "2030-01-01 00:00:00 UTC" +%s   # Linux
# paste the output into OPEN_TIMESTAMP_UNIX_SECONDS
```

**Full configuration steps:**

```bash
# 1. Change the passphrase (shared.rs)
PASSWORD = b"your-new-passphrase";

# 2. Change the unlock time (shared.rs) — e.g. New Year's Day 2030
OPEN_TIMESTAMP_UNIX_SECONDS = 1893456000;

# 3. Write the secret to seal (read.txt)
echo "Only readable after the hour." > read.txt

# 4. Rebuild
cargo build --release --target x86_64-unknown-linux-musl
```

> Note: at build time, `read.txt`'s modified time, created time, and last `git` commit author are embedded as metadata and shown as an anti-forgery proof during the reveal.

### Usage

```bash
./hello_old            # interactive; passphrase echoed as *
printf '114514\n' | ./hello_old   # piped automation
```

Before the hour → refused, time remaining shown; at the hour → enter passphrase → 7-layer decryption → ceremonial reveal → press `q` to burn and self-delete.

### Pocket-Sized Storage & Ceremonial TUI

- **Small enough to carry anywhere**: the statically linked binary is only **~945 KB** (under 1 MB) — fits on a thumb drive or in a single message. Slip it in your pocket, mail it to the future.
- **Zero-dependency, plug and play**: no runtime, no libraries — copy it to any x86_64 Linux machine and run.
- **Ceremonial full-screen TUI**: unlocking is an audio-visual ritual —
  - opening full-screen garble flash + scanline sweep (~2 seconds);
  - six-stage green decryption progress bar;
  - content revealed character by character with glow trail and live status bar;
  - press `q` to burn: warning line typed out → block cursor blinks → seven progress bars count down in reverse → red garble flicker → screen clears.
- **Terminal-adaptive**: full ANSI color support, width auto-fit, cursor/font styling — best on dark terminals.

### More Highlights

- **Passphrase erased on entry**: echoed as `*`, then zeroized from memory the instant it is consumed — never lingers.
- **Zero-punishment retries**: a wrong passphrase just re-prompts — no lockout, no penalty. Only *tampering* triggers self-destruct, so legit users are treated gently.
- **Manual NTP fallback**: if every public server is unreachable, it interactively prompts for a custom NTP host — unlockable even offline or behind a firewall.
- **Signal immunity**: `SIGINT`/`SIGTERM`/`SIGHUP`/`SIGQUIT`/`SIGTSTP`/`SIGPIPE` are all ignored; only the watchdog's `SIGKILL` can terminate it — Ctrl+C cannot kill it.
- **Watchdog, four-fold self-destruct**: stale heartbeat, tracer attachment, in-memory key tampering, or binary modification — any one triggers instant `SIGKILL`.
- **Triple memory defense**: `mlock` to pin pages, `PROT_NONE` guard pages, volatile zeroization with a memory fence — keys and plaintext live for milliseconds.
- **Release-grade hardening**: LTO + strip + `panic=abort` + single codegen unit shrink the reverse-engineering surface to a minimum.
- **Pure client, zero telemetry**: no backend, no logs, no network uploads — running it is privacy by construction.
- **Piped automation**: `printf 'pass' | ./hello_old` works, so it slots into scripts and CI.
- **Build-time randomization, anti-fingerprint**: SALT is regenerated every build, so each binary ships different keys — no master key for every door.
- **Self-deleting to the end**: press `q` and the binary removes itself from disk — not even the program survives.
- **Tamper-proof signing**: the self-signature private key is **not derivable from source** — it comes from the `HELLO_OLD_SELF_SIGN_KEY` env var (64 hex) or the git-ignored `signing/selfsign.key` file. `build.rs` embeds the matching public key into the binary, and at runtime verification trusts only that embedded key (never the one in the overlay), so re-signing with a fresh random key does not work. Editing even one byte of a signed binary makes it refuse to run (exit 138). Without the secret, `cargo build --release` *refuses to build* and `xtask` *refuses to sign* — no forgeable artifact can be produced. Guard the key offline as a secret; if it leaks, tamper protection is void and you must regenerate and rebuild.

### Build & Sign

```bash
# 0. (one-time) generate the self-sign private key — keep offline, never commit
python -c "import secrets;print(secrets.token_hex(32))" > signing/selfsign.key
#    or export HELLO_OLD_SELF_SIGN_KEY="<64 hex chars>" instead of the file

cargo build --release          # refuses to build without the key
cargo run --manifest-path xtask/Cargo.toml -- \
    target/release/hello_old target/release/hello_old   # sign in place (refuses without key)
```

Unsigned binaries, or binaries whose signature private key does not match the build-time key, are refused at startup — a deliberate integrity gate.

### Cracking Difficulty

One must simultaneously break the time gate, the NTP consensus, 11 stacked algorithms, RustyVM key reconstruction, seccomp/memory/anti-debug defenses, and the constant-time side-channel measures — all while every failed attempt risks the whole program self-destructing. No single point yields the key; it exists only in volatile memory, alive for milliseconds. **Unless you hold both kernel-level and hardware-level attack capability, that door stays shut until the hour comes.**

> See [FLOWCHART.md](FLOWCHART.md) for the full pipeline diagram.
