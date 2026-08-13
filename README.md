# hello_old

AI made
它不是一把普通的钥匙，而是一座**七道城门嵌套、各自挂着不同锁**的城堡。盗贼必须依次撬开每一道门，任何一道门察觉到可疑的动静，整座城堡就会**当场自焚**，连同门里的秘密一起化为灰烬，连一页纸都不留下。

它固执到什么程度？它**不信任任何一块主板电池**——时钟会坏、电池会耗干、未来机器的年月日你无从预料。所以它把裁决权交给天上散布的许多座"星钟"（NTP 服务器），只有它们彼此对齐、且与你手表的读数相合，它才肯转动第一道铰链。你可以把它装进口袋、带到几十年后的任何一台 x86_64 机器上，它不挑主人，只认时间与口令。

它的用途很简单也很庄重：**把一段文字封存到指定时刻之后才交付**——遗嘱、密钥备份、穿越时空的密信。它是一张"到点才撕开的信封"。

推荐用法：

1. 把 `hello_old` 复制到目标机器，运行它；
2. 到点之前，它只会冷漠地告诉你"门还锁着"；
3. 到点之后，输入口令，它会以仪式般的节奏逐字放出文字；
4. 读完按 `q`，它删除自己——**读后即焚，阅后无痕**。

> 把最珍贵的东西放进去，然后放心地把门关上。它替你把钥匙和门锁一起嚼碎咽下。

---


### 全链路：11 种算法叠加，7 层加密链 + 运行时防护

解密并非一蹴而就，而是一条必须逐层击穿、且任何一步出错即自我毁灭的链式流程：

```
口令
 │  Argon2id (256 MiB, 4 iter, 8 lanes)
 ▼
主密钥 → RustyVM 自定义虚拟机（16 条指令，常量时间执行）
 │  从加密的 km.bin 中重建 k1∥k2
 ▼
6 把 HKDF-SHA256 包裹密钥
  ├─► RSA-4096-OAEP 私钥解密 ────────────► shard1
  ├─► Kyber-1024 (ML-KEM) 解封装 ────────► shard2
  ├─► Classic McEliece-6960119f 解封装 ──► shard3
  ├─► FrodoKEM-1344 解封装 ──────────────► shard4
  ├─► Dilithium-5 (ML-DSA-87) 验签 ─────► shard5 = blake3(公钥)
  ├─► SM3-256 国密哈希 ─────────────────► shard6 = sm3(公钥) ①
  └─► Serpent-256-SIV 解密 DEK 包裹 ─────► DEK
  │
  ▼
  六片 shard XOR 重组 32B 数据密钥 (DEK) ②
  ▼
  Ed448 + Dilithium-5 双重签名验证 (时间戳 ∥ DEK ∥ SHA3-256(密封载荷))
  ▼
  Serpent-256-SIV 解密载荷
    └─► 用 k1∥k2∥SALT 密钥流去白化
    └─► LZMA 解压回 [meta_len][meta_json][正文]
    └─► 明文直接写入锁定 + 护栏页缓冲，不经普通堆
  ```

  - 共 6 片 shard XOR 得 256-bit DEK：`RSA ⊕ Kyber ⊕ McEliece ⊕ FrodoKEM ⊕ SHA3-256(Dilithium VK) ⊕ SM3-256(Dilithium VK)`。
  - 最后两片分别用 **BLAKE3** 与 **SM3** (国密) 哈希同一把 Dilithium 公钥——两种独立哈希，缺一即使 DEK 重组失败。
  - 载荷先 LZMA 压缩、再用 `k1∥k2∥SALT` 派生的 blake3 密钥流逐字节异或白化，最后才进 Serpent-SIV——即便拿到 DEK 也仍需密码派生的 k1∥k2 才可还原明文。

**破解者必须同时面对：**

| 维度 | 强度 |
|---|---|
| 密钥派生 | Argon2id：256 MiB 内存硬、4 次迭代、8 路并行，暴力成本高昂 |
| 后量子 KEM ×4 | RSA-4096-OAEP + Kyber-1024 + McEliece-6960119f + FrodoKEM-1344，任一不破则 DEK 重组失败 |
| 签名 ×2 | Ed448 + CRYSTALS-Dilithium-5（ML-DSA-87），篡改即自毁 |
| 对称加密 | Serpent-256-SIV：认证加密 + 不可约简的安全证明 |
| 自研 VM | 16 条指令的 RustyVM，密钥永不作为连续明文存在 |
| 时间门 | 本地时钟必须与多台 NTP 服务器对齐在 ±10 秒内，否则拒绝 |
| 运行时防护 | seccomp-BPF、mlock + guard pages、watchdog、TracerPid、LD_PRELOAD/RWX 检测、读后自毁 |

### 侧信道防护

- **常量时间全套**：秘密相关的比较（`ct_eq`）、条件移动、索引访问全部基于 `subtle` 库，无秘密依赖分支。
- **固定步数解密**：错误口令路径执行与真实派生等量的 `burn_cycles` dummy 计算（约 800 万轮依赖链运算），成功/失败耗时不可分辨。
- **缓存时序防护**：密钥与载荷写入后立即 `clflush` 逐条缓存行驱逐（`flush_mem`），防止 cache-timing 侧信道读取。
- **读后即焚**：载荷展示完毕、退出前强制零化 + 解除内存映射 + 删除自身二进制。

### 时间门控（面向未来）

- 解锁时间在构建时嵌入并双重加密，运行时用常量时间比较校验（`ct_eq`）。
- 判定只用 **NTP 共识时间**（5 台服务器取中位，±10s 容差），本地时钟仅作宽松参考，不依赖任何主板 RTC / BIOS 时钟。
- 单调时钟锚点检测墙钟跳变，防时钟回滚。

### 构建
推荐
```bash
cargo build --release --target x86_64-unknown-linux-musl
# 产物: target/x86_64-unknown-linux-musl/release/hello_old
```

- 通用 x86-64 指令集（`target-cpu=x86-64`），可复制到任意 x86_64 Linux 机器运行，不绑定构建机 CPU 特性。
- 完全静态链接，无任何运行时依赖。
- 口令在 `shared.rs`（默认 `114514`），SALT 每次构建随机生成。
- **release 产物必须签名**：签名私钥由 `HELLO_OLD_SELF_SIGN_KEY` 环境变量或 `signing/selfsign.key`（git 忽略）提供，缺密钥则拒绝构建；产物需 `cargo xtask sign` 后才会运行（见下方「构建流程」）。

### 配置（改这 4 处即可定制）

程序的所有可调项集中在两个文件：`shared.rs`（口令、时间、NTP）与 `read.txt`（要封存的秘密）。改完重新 `cargo build` 即可。

| 配置项 | 位置 | 说明 |
|---|---|---|
| 口令 | `shared.rs` → `PASSWORD` | 运行时解锁口令，改完重新构建即生效，勿在二进制里泄露 |
| 解锁时间 | `shared.rs` → `OPEN_TIMESTAMP_UNIX_SECONDS` | Unix 秒；到点后才放行 |
| 秘密文本 | `read.txt` | 要封存的内容，构建时嵌入并加密 |
| NTP 服务器 | `shared.rs` → `NTP_SERVERS` | 时间共识来源，可换成你信任的服务器列表 |
| 时钟容差 | `shared.rs` → `CLOCK_DRIFT_LIMIT_SECONDS` | 本地时钟与 NTP 的最大允许偏差（默认 10s） |

**解锁时间怎么算？** 用任何 Unix 时间戳转换工具，例如：

```bash
date -d "2030-01-01 00:00:00 UTC" +%s   # Linux
# 把输出填进 OPEN_TIMESTAMP_UNIX_SECONDS
```

**完整配置步骤：**

```bash
# 1. 改口令（shared.rs）
PASSWORD = b"你的新口令";

# 2. 改解锁时间（shared.rs）—— 比如 2030 年元旦
OPEN_TIMESTAMP_UNIX_SECONDS = 1893456000;

# 3. 写入要封存的秘密（read.txt）
echo "这是只有到点才能读的话。" > read.txt

# 4. 重新构建
cargo build --release --target x86_64-unknown-linux-musl
```

> 注意：构建时 `read.txt` 的修改时间、创建时间、最后一次 `git` 提交作者会以元数据形式一起封存，展示时作为防伪信息显示。

### 使用

```bash
./hello_old            # 交互式运行，口令以 * 回显
printf '114514\n' | ./hello_old   # 管道自动化
```

到点前 → 拒绝并显示剩余时间；到点后 → 输入口令 → 7 层解密 → 仪式化展示 → 按 `q` 自毁删除。

### 便携储存与仪式化 TUI

- **小到可随身携带**：静态编译后的二进制仅约 **945 KB**（不到 1 MB），一颗 U 盘 / 一次聊天发送即可带走。放进口袋、寄往未来，毫无负担。
- **零依赖即插即用**：不需要运行时、不需要安装任何库(指静态编译)，复制到任意 x86_64 Linux 机器上直接运行。
- **仪式化全屏 TUI**：解锁过程是一场视听仪式——
  - 开场全屏乱码闪屏 + 扫描线扫过（约 2 秒）；
  - 绿色解密序列进度条六阶段推进；
  - 内容逐字"吐出"，带余光残影与状态栏；
  - 最后 `q` 触发自毁：警告行逐字打出 → 方块光标闪烁 → 七条进度条倒序清零 → 红色乱码闪动 → 清屏。
- **全终端适配**：完整支持 ANSI 色彩、行宽自适应、光标/字体样式控制，深色终端下效果最佳。

### 更多亮点

- **口令即输入即零化**：口令以 `*` 回显，验证后立即从内存中清零，不驻留一毫秒。
- **错误口令零惩罚重试**：输错只提示重试，不锁定、不惩罚——只有检测到**篡改**才触发自毁，对正常用户极度宽容。
- **NTP 失败可手动救场**：全部公共服务器不可达时，交互提示输入自定义 NTP 主机，离线/内网环境也能解锁。
- **信号免疫**：`SIGINT`/`SIGTERM`/`SIGHUP`/`SIGQUIT`/`SIGTSTP`/`SIGPIPE` 全部忽略，只有 watchdog 的 `SIGKILL` 能终止进程——按 Ctrl+C 也杀不死它。
- **Watchdog 四重自毁**：心跳超时、调试器附着（TracerPid）、内存密钥被篡改、二进制被改，任一发生立即 `SIGKILL`。
- **内存三重防护**：`mlock` 锁页防换出、`PROT_NONE` guard page、volatile 零化 + 内存屏障，密钥与明文生命期以毫秒计。
- **发布级优化**：LTO + strip + `panic=abort` + 单 codegen-unit，逆向面被压到最小。
- **纯客户端、零遥测**：无后端、无日志、无网络上传，运行即隐私。
- **管道自动化**：支持 `printf '口令' | ./hello_old`，可集成进脚本与 CI。
- **构建随机化反指纹**：每次构建随机生成 SALT，每份二进制密钥都不同，杜绝"一把钥匙开所有门"。
- **自毁级删除**：读完 `q` 后从磁盘删除自身二进制，连程序本尊都不留。

### 破解难度

需要同时突破：时间门控、NTP 共识、11 种算法叠加、RustyVM 密钥重建、seccomp/memory/反调试防护、常量时间侧信道防护——并在每次尝试失败时冒着整个程序自毁的风险。任何单点突破都无法还原密钥；密钥只存在于运行时内存，且生命期以毫秒计。**除非你同时掌握内核级与硬件级攻击能力，否则这扇门在到点之前，就是关着的。**

> 完整全链路流程图见 [FLOWCHART.md](FLOWCHART.md)。

### 运行时加固清单（本构建新增）

> 本次构建在原有七层加密链之上，追加了独立成组的运行时加固。所有加固在 debug 构建下已验证通过；release 构建需先经 `cargo xtask sign` 签名，否则程序拒绝运行。

**A — 行为收敛**
- 删除 `NO_SELF_DESTRUCT` 编译开关：自毁不再可被条件编译关掉，路径唯一、行为一致。
- `build.rs` 的全部信息泄露输出改为 `binfo!` 宏，仅 `debug_assertions` 下打印；release 构建静默，不给逆向者提供算法/密钥布局提示。

**B — 文件自锁与烧毁清理**
- Windows 上 `harden_exe()` 以 `FILE_SHARE_READ` 独占打开自身 exe 句柄并持有到进程结束，运行时他人无法删除/移动/覆盖它；烧毁路径先 `unlock_exe()` 释放句柄，再删除二进制与诊断日志。

**C — 时间门多校验点 + 全路径恒定**
- 时间判定改写为非平凡算术谓词 `time_gate_open()`，在二进制中不以裸 `now < open_ts` 出现，静态 patch 难以定位。
- 门锁判定不再提前退出：**无论门锁与否都跑完整七层解密**，运行时长相一致，侧信道无法从耗时区分锁定/解锁。
- 解密链末尾二次重读系统时钟复核；watchdog 周期校验（`set_open_ts` 武装后，回拨时钟即 fail-fast）。

**D — Windows 反调试/反注入**
- 绕过 `IsDebuggerPresent` hook：内联汇编直读 `gs:[0x60]` PEB 的 BeingDebugged 标志。
- `NtQueryInformationProcess(ProcessDebugPort=7)`：从 ntdll 导出表（手写 PE 解析，绕 GetProcAddress hook）取函数地址直调。
- `EnumWindows` 标题枚举：识别 x64dbg/x32dbg/OllyDbg/IDA/Immunity/WinDbg 窗口。
- 所有调试器检测失败即 fail-fast 自杀。

**S — 侧信道与内存卫生**
- 成功/失败路径对称 burn（`timing_equalize`）+ 随机抖动（`timing_jitter` 0–8ms）。
- 密码读取改为固定 127 字节栈缓冲 + `VirtualLock`/`mlock` 锁页 + volatile 清零；不再用堆 `Vec`。
- 解密后刷栈（`scrub_stack`）+ `flush_mem` 补 `mfence/lfence`。
- 所有敏感比较（watchdog 密钥哈希、Serpent-SIV tag、DEK 校验）改用常数时间 `ct_eq`。

**X1 — 全文件 Ed448 自签名（防篡改）**
- 签名私钥**不来自源码**：由环境变量 `HELLO_OLD_SELF_SIGN_KEY`（64 hex）或 git 忽略的密钥文件 `signing/selfsign.key` 提供，持有源码者无法重新派生。
- build.rs 构建时把对应**公钥内嵌进二进制**，运行时 `verify_self_signature` 只认内嵌公钥、不信任 overlay 里自带的 vk——用自己生成的随机密钥重签无效。
- `xtask sign` 对 exe 全文件做 Ed448 签名（约 187 字节签名档，追加在 PE overlay 末尾）。
- 改一字节即校验失败、拒绝运行（exit 138）。
- **无密钥即不可伪造**：缺少密钥时 `cargo build --release` 直接报错、`xtask` 拒绝签名，杜绝产出可被重签的产物。密钥文件须作为机密离线保管，泄露则防篡改失效。

**X2 — 内存滚动加密**
- 解密内容写入安全缓冲后立即用进程随机掩码 XOR 加密；watchdog 每 400ms 滚动更换掩码，任意时刻 dump 得到的是已被滚动的密文。
- 显示前才解密，随后掩码清零。明文驻留窗口以毫秒计。
- LZMA 解压直接落在锁定 + `PROT_NONE` 护栏页缓冲（限界 `Write`），明文不经普通堆分配，防换出/防转储。

**X3 — 双 watchdog 互监控**
- 两个独立 watchdog 线程共享心跳槽；任一被 kill，另一方检测到兄弟心跳过期即 fail-fast 自杀。主线程 `beat()` 同步刷新心跳。

**X6 — VM 降级**
- 检测 hypervisor/SMBIOS 指纹（VMware/VirtualBox/QEMU/KVM/Xen）后，RustyVM 每指令额外 250µs 延迟并输出警告——拖慢而非封禁。

**M — 杂项加固**
- M1 周期反调试：`debugger_present()` 从 watchdog 每 400ms 重跑，运行中挂调试器也会 fail-fast（不只在启动时检测一次）。
- M3 进程迁移策略：动态加载 `SetProcessMitigationPolicy`，启用 ASLR（底部随机+强制重定位+高熵）、动态代码禁用、严格句柄检查、Control Flow Guard、镜像加载策略（禁远程/低标级图像、优先 System32）。
- M4 不透明谓词：`time_gate_open` 内插恒真/恒假代数欺骗，掩埋真实时间判定。
- M5 字符串混淆：签名 MAGIC 与调试器窗口标题以 XOR 字节存于 `.rodata`，运行时解掩，静态扫描看不到明文。
- M6 内嵌 blob 完整性：VM 程序字节码的 blake3 由 build.rs 生成内嵌，启动校验，内存 hook 拒绝运行。
- M7 代码段内存自校验：watchdog 对运行中 `.text` 内存做基线 + 周期 hash 对比，运行期被改写即 fail-fast（补 X1 只防启动前的缺口）。
- M8 调试对象侦察：`NtQueryInformationProcess` 追加 `ProcessDebugObjectHandle(0x1e)` 与 `ProcessDebugFlags(0x1f)`。

**构建流程（自签名密钥先行）**
```
# 0.（一次性）生成自签名私钥 —— 请离线/私密保管，勿提交
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
$b = New-Object byte[] 32; $rng.GetBytes($b)
([System.BitConverter]::ToString($b) -replace '-','').ToLower() | Set-Content signing/selfsign.key
#   或用环境变量替代文件：$env:HELLO_OLD_SELF_SIGN_KEY = "<64 hex>"

cargo build --release              # 无密钥则拒绝构建（不产出可伪造产物）
cargo run --manifest-path xtask/Cargo.toml -- \
    target/release/hello_old.exe target/release/hello_old.exe   # 签名（就地覆盖，无密钥则拒绝）
```
未经签名、或签名私钥与构建时不匹配的二进制会拒绝运行——这是有意为之的完整性门。任何对已签名二进制的字节级修改都会导致校验失败。
