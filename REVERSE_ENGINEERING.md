# Reverse engineering — the MRiYA router program

Target program: `AN225ksocfZpbPVEbwffiANbtUdYbySM3WJ6dbsYAqij`
Program-data PDA: `HBTxd8CRuqSvf8XN8x3X4yGjheavCF5yRSgnLCPje15q`
Upgrade authority: `MRiYA4oN3158fCV8evhuCofrDzbHyYvYnGZUDJvoCsa`
ELF compiled size: 378,968 bytes

The program is deliberately marked `anchorVerify: unverified` — no source / IDL
published — but the **bytecode itself is public** (it lives on-chain in the
program-data PDA). What follows is what we can recover purely from that.

---

## 1. Build & toolchain leak

The Rust compiler embeds **panic-site source paths** into the binary's `.rodata`
section so the runtime can produce useful stack traces. Even with release-mode
symbol stripping, those paths survive. From this binary:

```
/Users/runner/work/platform-tools/platform-tools/out/rust/library/alloc/src/slice.rs
```

Two things to note:

- **`/Users/runner/...` is the canonical home directory of the GitHub Actions
  macOS runner image.** The router is built in a CI pipeline on GitHub-hosted
  macOS runners.
- **`platform-tools/`** is the Solana official Rust toolchain (the BPF-targeted
  Rust fork). The team uses the official Solana toolchain, not a custom fork.

A more meaningful leak is the program's own source-file paths, embedded by
the same panic-location mechanism. These give us a **complete catalog of every
DEX module the router compiles in**:

```
src/lib.rs                            — main library entry
src/entrypoint_nostd.rs               — custom no-std program entrypoint
src/dex/dex_raydium_cl.rs             — Raydium CLMM
src/dex/dex_raydium_lpv4.rs           — Raydium AMM v4 (LP v4)
src/dex/dex_raydium_cpmm.rs           — Raydium CPMM
src/dex/dex_orca_whirlpool_v2.rs      — Orca Whirlpools v2
src/dex/dex_orca_token_swap_v2.rs     — Orca v1 / TokenSwap v2
src/dex/dex_meteora_dlmm.rs           — Meteora DLMM
src/dex/dex_meteora_pools.rs          — Meteora classic Pools
src/dex/dex_meteora_damm_v2.rs        — Meteora DAMM v2
src/dex/dex_pump_swap.rs              — PumpSwap AMM
src/dex/dex_saber_stable_swap.rs      — Saber Stable Swap
src/dex/dex_saros_amm.rs              — Saros AMM
src/dex/dex_fusion.rs                 — Fusion AMM
src/dex/dex_humidifi.rs               — HumidFi
src/dex/dex_bizonfi.rs                — BiSoNFi (BISONFI)
src/dex/dex_token_mill_v2.rs          — Token Mill v2
```

That's **17 DEX integrations**, naming the prop-AMMs that previous analysis
couldn't identify. The bot is built to arbitrage against **all of these
venues**, dispatching to the appropriate `dex_*.rs` module based on which
the client tx asks it to invoke.

### 1.1 Identification of previously-unknown program IDs

Cross-referencing the source-file names with the program IDs we observed in
the wallet's transaction history:

| `dex_*.rs` module    | program ID observed on-chain | confidence |
| --- | --- | --- |
| `dex_humidifi.rs`    | `9H6tua7jkLhdm3w8BvgpTn5LZNU7g4ZynDmCiNN3q6Rp` | high — HumidFi is the well-known prop-AMM with ~23% of Jupiter prop-AMM volume; this is the highest-volume unknown |
| `dex_fusion.rs`      | `fUSioN9YKKSa3CUC2YUc4tPkHJ5Y6XW1yz8y6F7qWz9`  | very high — vanity prefix matches exactly |
| `dex_bizonfi.rs`     | `BiSoNHVpsVZW2F7rx2eQ59yQwKxzU5NvBcmKshCSUypi` | very high — vanity prefix `BiSoN…` matches `bizonfi.rs` |
| `dex_meteora_damm_v2.rs` | `cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG` | medium — "cp amd" suggests "constant-product AMM (DAMM)"; co-occurs heavily with PumpSwap consistent with Meteora's role |
| `dex_token_mill_v2.rs` | one of {`proVF…`, `HpNfyc…`, `24Uqj9JC…`, `REALQqN…`} | unconfirmed — needs additional identification |

The router definitely contains support for Token Mill v2 even though Token
Mill's program ID isn't directly observable from this dataset's frequency
profile. Means the bot will arb that venue whenever opportunity arises.

---

## 2. Entrypoint & dispatcher

### 2.1 The custom no-std entrypoint

The dynamic symbol table (`.dynsym`) shows exactly two exported functions
and six syscalls:

```
custom_panic              0x0004d8d0  40 bytes
entrypoint                0x0004d5a8  704 bytes
sol_invoke_signed_c       (external syscall — CPI to other programs)
sol_log_                  (external syscall — write to program log)
sol_get_rent_sysvar       (external syscall — read rent sysvar)
sol_try_find_program_address  (external syscall — PDA derivation)
abort                     (external syscall — runtime termination)
sol_memcpy_               (external syscall — byte copy)
```

The fact that the file is named `entrypoint_nostd.rs` and the program exports
exactly two symbols (entrypoint + custom_panic, plus syscalls) tells us:

- **The program does NOT use Anchor's standard entrypoint.** Anchor's
  `#[program]` macro generates a dispatcher that adds ~5-10k CU of overhead
  per tx (discriminator check, account validation, error wrapping). This
  router skips all of that.
- **`#[no_std]`** — no Rust standard library. Just `core`. That removes
  several KB of bloat (panic handler, formatting, allocator) — replaced with
  the `custom_panic` 40-byte stub.
- **Manual instruction dispatch.** Instead of Anchor's sighash-based dispatch,
  the entrypoint reads the first byte(s) of instruction data and jumps to the
  appropriate handler. We can prove this from the .text opcode counts (see
  §3) — there are **1,824 JEQ_IMM instructions**, which is the SBPF "jump if
  equal to immediate" opcode used for switch-style dispatch on small integer
  tags.

### 2.2 No Anchor sighashes embedded

We checked the binary for the SHA-256 hash prefixes of common method names
(Anchor convention: `sighash("global:method_name") = first 8 bytes of
sha256("global:method_name")`). **No matches were found.** Methods like
`execute`, `swap`, `swap_two`, `route`, `arb`, `tip_jito`, `raydium_swap`,
`orca_swap`, etc. — none of their Anchor sighashes appear in the binary.

This is consistent with the no-Anchor finding above. The dispatch is by
**small integer tag** (single byte or 2-byte enum-discriminant) rather than
8-byte SHA-256 prefix. This saves CU on every dispatch — the tag comparison
is one SBPF instruction; an Anchor sighash check is several.

---

## 3. Code shape — what the bytecode tells us

The `.text` section is **352,216 bytes** = approximately **44,027 SBPF
instructions** (most are 8 bytes; LDDW is 16). Opcode-frequency breakdown:

| opcode | meaning | count |
| --- | --- | ---:|
| `LDXDW` (0x79) | 64-bit memory load | **7,664** |
| `STXDW` (0x7b) | 64-bit memory store | **7,718** |
| `MOV_IMM_64` (0xb7) | load 64-bit constant into register | **6,638** |
| `STXB` (0x73) | byte store | **3,479** |
| `MOV_REG_64` (0xbf) | register copy | **2,839** |
| `LDXB` (0x71) | byte load | **2,812** |
| `JNE_IMM` (0x55) | jump if not equal to immediate | **2,359** |
| `JEQ_IMM` (0x15) | jump if equal to immediate | **1,824** |
| `LDDW` (0x18) | load 64-bit double-word constant | **813** |
| `JA` (0x05) | unconditional jump | **680** |
| `CALL_IMM` (0x85) | function call / syscall | **484** |
| `LDXW` (0x61) | 32-bit memory load | **221** |
| `EXIT` (0x95) | function return | **79** |

What this tells us:

- **At minimum 79 distinct functions** (each ends with an EXIT). Realistic
  count is higher because compilers fold EXITs in tail-call optimization.
  For a 17-DEX router this is consistent: each `dex_*.rs` module likely
  exposes 2-5 functions (swap, get_quote, build_accounts, etc.) → 34-85
  functions total. The 79 lower bound aligns.
- **484 internal call sites** — that's the call graph density. The
  dispatcher calls into per-DEX modules; per-DEX modules call helpers
  (account parsing, PDA derivation, slippage check, CPI to the actual DEX
  program); helpers call syscalls.
- **64-bit operations vastly dominate 32-bit** (LDXDW 7,664 vs LDXW 221).
  Solana pubkeys, token amounts, and slot numbers are all u64 — this is the
  expected pattern for a Solana program. The router is doing a lot of
  amount/balance math.
- **1,824 JEQ_IMM + 2,359 JNE_IMM = 4,183 imm-compare branches.** This is
  the discriminator-comparison density that confirms a "many small-integer
  tags → many handlers" dispatch model. A typical 17-arm switch needs ~17
  JEQ_IMM per level; the bot has nested dispatches (top-level by DEX, then
  by swap-direction, etc.) which multiplies into the thousands observed.
- **6,638 MOV_IMM_64 + 813 LDDW = 7,451 constant loads.** That's where every
  hardcoded address (System Program ID, wSOL mint, etc.), every literal
  constant, every error code, and every CU budget lives. The program is
  saturated with hardcoded values — this is typical of release-compiled
  Rust where the compiler inlines constants aggressively.

### 3.1 What's NOT in the binary

- **No 32-byte sequences matching the major DEX program IDs.** We searched
  for Meteora DLMM, PumpSwap, Orca Whirlpools, Raydium CLMM/CPMM/AMM v4,
  Jupiter v6, Tessera, ZeroFi, GoonFi, Manifest, etc. **Only System Program
  and wSOL mint** appear as plain 32-byte pubkey constants.

  This means the DEX program IDs are **NOT compiled into the binary** —
  they are passed by the client in the account-meta list of each tx.

  Why? Two reasons:
  1. **Flexibility**: when a new DEX appears, the operator can add a new
     `dex_X.rs` module and update which pubkey gets passed in the account
     meta. **No program redeploy required.** This explains how Tessera and
     similar venues can be added to the bot's repertoire on a continuous
     basis without an on-chain program upgrade.
  2. **Bytecode size minimization**: if you have 17 DEXes × 32-byte pubkey =
     544 bytes saved. Trivially small here, but as the strategy adds more
     venues it scales.

- **No Jito tip account pubkeys.** Same reason — they're passed by the
  client. The router does the tip transfer when the tx asks it to (the
  client provides the destination account in the account meta).

---

## 4. Inferred architecture

Putting the on-chain bytecode together with the off-chain transaction
patterns we already mapped, the router program's architecture is:

```
                          ┌────────────────────────┐
                          │  entrypoint (704 B)    │
                          │  src/entrypoint_nostd  │
                          │                        │
                          │  1. parse instruction  │
                          │     data — read tag    │
                          │  2. parse accounts —   │
                          │     get DEX pubkey(s)  │
                          │     from account list  │
                          │  3. dispatch on tag    │
                          │     (1-byte enum)      │
                          └─────────┬──────────────┘
                                    │
        ┌───────────────────┬───────┼───────────────┬───────────────┐
        ▼                   ▼       ▼               ▼               ▼
┌──────────────┐  ┌──────────────┐  ┌───────────┐  ┌─────────┐  ┌─────────┐
│ dex_meteora_ │  │ dex_pump_    │  │ dex_orca_ │  │ dex_    │  │ ...     │
│  dlmm.rs     │  │  swap.rs     │  │  whirl…   │  │ humidi  │  │ (12     │
│              │  │              │  │  v2.rs    │  │  fi.rs  │  │  more)  │
│ build_meta() │  │ build_meta() │  │ build_…   │  │ build_… │  │         │
│ check_slip() │  │ check_slip() │  │ check_… │  │ check_… │  │         │
│ cpi_invoke() │  │ cpi_invoke() │  │ cpi_…   │  │ cpi_…   │  │         │
└──────┬───────┘  └──────┬───────┘  └─────┬───┘  └────┬────┘  └─────────┘
       │                 │                 │           │
       ▼                 ▼                 ▼           ▼
  ┌─────────────────────────────────────────────────────────┐
  │  sol_invoke_signed_c — Solana CPI syscall              │
  │  (Account list + signer seeds → leader)                 │
  └─────────────────────────────────────────────────────────┘
```

Per arb tx:

1. Client builds an instruction whose **data field** starts with a small
   integer tag (likely 1 byte = "execute multi-leg arb" + variant info)
   and contains parameters (min-out, expected-in amounts, etc).
2. Client sets the **account-meta list** to include:
   - The wallet's wSOL account
   - The intermediate token's ATA
   - The wSOL account again (for the return leg)
   - The first DEX's program ID + its pool/vault accounts
   - The second DEX's program ID + its pool/vault accounts
   - (Optional) The Jito tip account
3. Router entrypoint reads the tag, identifies which two DEX modules to
   invoke (based on positions in account list), and calls each module's
   handler in sequence.
4. Each per-DEX module:
   - Parses its slice of the account list
   - Builds the inner CPI instruction in the format that DEX expects (each
     DEX has a different instruction layout — Meteora DLMM is different
     from Raydium CLMM is different from HumidFi)
   - Invokes via `sol_invoke_signed_c`
5. After both legs complete, the router compares the wallet's wSOL balance
   delta against `min_profit` from the instruction data. If the delta is
   below threshold, the entire tx aborts (everything rolls back; the bot
   only loses fees).
6. If profit assertion passes, optionally transfer Jito tip and exit OK.

---

## 5. Performance optimizations the router uses

Counting micro-optimizations observable in the binary:

| optimization | evidence | CU savings (est.) |
| --- | --- | ---:|
| Custom `no_std` entrypoint instead of Anchor | `entrypoint_nostd.rs` source file, only 8 dynamic symbols, no Anchor sighashes | ~5-10k per tx |
| Small-integer tag dispatch (not 8-byte sighash) | 1,824 JEQ_IMM in .text; no Anchor sighashes embedded | ~200 per dispatch |
| `setLoadedAccountsDataSizeLimit` instruction per tx | observed in every tx's outer-ix template | locks-in account read budget; cheaper than over-loading |
| Single CPI per leg (no double-routing through Jupiter) | router directly invokes DEX programs, not Jupiter aggregator | ~30k per leg |
| DEX program IDs passed in account list (not hardcoded) | no DEX program IDs in binary | enables new-DEX addition without redeploy |
| Inlined constants (very heavy MOV_IMM_64 + LDDW use) | 7,451 constant-loads in .text | every immediate fits in instruction; no PC-relative load needed |
| Pre-positioned ATAs (no createAccount in arb txs) | 0.01% of txs include createAccount | ~5k per arb saved |
| Pre-positioned nonces (no nonce-init in arb txs) | 1,000+ nonces created upfront | ~3k per arb saved |
| Compact account-meta lists | tight outer-ix template (advanceNonce + ComputeBudget × 2-3 + router ix) | smaller tx = faster TPU forwarding |

Cumulative savings vs a naive Anchor + Jupiter-aggregator approach: probably
**40-80k CU per arb**, plus the failure-mode resilience from pre-positioned
infrastructure.

---

## 6. What we still can't recover

| concern | why bytecode alone won't tell us |
| --- | --- |
| Exact slippage / profit thresholds | These are passed in the instruction data, not hardcoded — they vary per tx |
| Which alt-signer was used per tx | Not visible from program; depends on the off-chain submitter |
| The off-chain monitoring + signal-generation stack | Lives outside the chain entirely |
| Specific RPC / SWQOS provider | Determined by the submitter's network config |
| How new DEXes are added | Requires watching git history of the operator's repo (private) |
| Algorithmic order-routing logic | Lives in the **client** (off-chain), not the on-chain router. The router is a *dumb executor* of routes the off-chain brain decides on. |

The last point is important: the on-chain router is **NOT where the
strategy lives**. It's a fast executor. The actual arb decision-making
(which pools to hit, in what order, with what slippage tolerance, when to
fire) all happens off-chain in the operator's monitoring / decision engine.

This is also a competitive moat: if a competitor reverse-engineered the
router byte-for-byte and reproduced it perfectly, they'd still have nothing
without the off-chain brain. The router is the easy half of the system.

---

## 7. Bottom line

**Yes, we can dump and meaningfully analyze the bot's router program.** The
key recoveries:

1. **Complete catalog of integrated DEXes** (17 modules including the
   previously-unknown HumidFi, Fusion, BiSoNFi, Meteora DAMM v2, Token Mill).
2. **Confirmed it's not Anchor** — custom `no-std` entrypoint with manual
   small-integer dispatch, deliberately stripped of all framework overhead.
3. **Confirmed dynamic DEX-ID model** — no DEX program IDs hardcoded, the
   router accepts any program ID via account-meta. This is the architectural
   reason the operator can add new venues (Tessera, GoonFi, ZeroFi) without
   redeploying.
4. **Code complexity estimate**: ~44k SBPF instructions, ~80+ functions, 484
   call sites. A real codebase, not a stub.
5. **Build evidence**: compiled on GitHub Actions macOS runners using the
   Solana platform-tools Rust toolchain — pro infrastructure.

What we *can't* recover from the bytecode is the strategy itself — the
profitable-route discovery logic, the slippage tuning, the pool-monitoring
signal — because that lives off-chain. The router is a lean, fast on-chain
executor; the brain is somewhere else entirely.

### Artifacts produced

```
data/reverse/an225_router.so      378,968-byte SBPF ELF (the program bytecode)
data/reverse/an225_meta.json      deploy slot / authority / size metadata
dump_router.py                    fetch + static-analysis pipeline
```

You can re-run `python dump_router.py` to re-fetch the bytecode (in case
the operator pushes an upgrade) and re-run the analysis end-to-end.
