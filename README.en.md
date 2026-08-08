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
 │  Argon2id (64 MiB, 3 iters)
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
 └─► Serpent-256-SIV unwrap DEK ─────────► DEK
 │
 ▼
five shards XOR-combined into the 32-byte Data Encryption Key (DEK)
 ▼
Ed448 + Dilithium-5 dual signature verify (ts∥DEK∥payload-hash)
 ▼
Serpent-256-SIV decrypt payload (153 bytes)
```

**An attacker must simultaneously defeat:**

| Dimension | Strength |
|---|---|
| Key derivation | Argon2id: 64 MiB memory-hard, 3 iterations — brute force is expensive |
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

### Cracking Difficulty

One must simultaneously break the time gate, the NTP consensus, 11 stacked algorithms, RustyVM key reconstruction, seccomp/memory/anti-debug defenses, and the constant-time side-channel measures — all while every failed attempt risks the whole program self-destructing. No single point yields the key; it exists only in volatile memory, alive for milliseconds. **Unless you hold both kernel-level and hardware-level attack capability, that door stays shut until the hour comes.**

> See [FLOWCHART.md](FLOWCHART.md) for the full pipeline diagram.
