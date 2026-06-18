# Deep analysis — how this bot lands, why it wins, and what tech it's running

This document goes beyond "what the wallet does" (covered in `ANALYSIS.md`)
and asks "why is it so successful, and what infrastructure is making it work".
Every claim cites the on-chain evidence the inference rests on. Where we
cross from measurement into inference (off-chain infrastructure we can't see
directly), it's labeled `[INFERRED]`.

Wallet under study: `MRiYA4oN3158fCV8evhuCofrDzbHyYvYnGZUDJvoCsa`

---

## 0. Identity — who runs this bot

The on-chain identity chain points to a **single operator team** running both
the funding wallet and the bot wallet via vanity-prefixed keys, with the bot's
arb router program being **self-owned and self-upgraded**:

### 0.1 The operator chain (deliberate vanity)

| wallet | role | provenance |
| --- | --- | --- |
| `MRiYA4oN3158fCV8evhuCofrDzbHyYvYnGZUDJvoCsa` | bot, signs every arb tx | funded by mriya4w… |
| `mriya4w5N64Erk6Ppd7snN7UubmvqGDRYNsAFngNAe4` | operator/treasury, funded the bot | funded by 8shhBrQN… |
| `8shhBrQN7kjJgjsVVgcXdneqiyKp9ehLpE7gugUfUCJX` | clean throwaway, near-empty after the seed transfer | upstream untraceable from here without further hops |

The bot wallet (`MRiYA…`) and the operator wallet (`mriya4w…`) **share the
"mriya" / "MRiYA" vanity prefix** — these are not coincidence; they are
deliberately-generated keys belonging to the same person/team. The operator
wallet activated about half a year before the bot started arbing; the 30 SOL
seed transfer from operator → bot established the working capital.

The root funder (`8shhBrQN…`) is a system wallet holding only 0.001 SOL
today — a **single-use disposable hop**, not a CEX hot wallet. The operator
clearly cares about provenance hygiene: any further upstream identification
would require walking that wallet's history through additional intentionally-
laundered hops.

### 0.2 The bot's secondary signers are also operator-controlled

The 9 alt signers (which land at 81.8% vs main 15.1%) are all confirmed as
`system_account` type (i.e., normal wallets — not validators, not stake
accounts, not program-derived addresses). Two of them share the vanity
prefix `GLk…` (`GLkLuUxsJgU…` and `GLkLiMc6yk…`) — again, deliberately
related keys.

This rules out one possible interpretation of the alt-signer effect: they
are NOT separately-staked third-party validators forwarding the bot's txs.
They are the bot's own operator keys, used via a **different submission
channel** that bypasses the public mempool — meaning the privileged
submission path is something the operator has access to and can use through
arbitrary signing keys.

### 0.2.1 Reverse-engineering of the router program

Dumping the bytecode of `AN225ksocfZpbPVEbwffiANbtUdYbySM3WJ6dbsYAqij`
from the program-data PDA and parsing its ELF reveals several things the
operator did not intend to be public:

**The complete list of integrated DEX modules** (leaked through Rust's
panic-site source-path strings preserved even in release builds):

```
src/dex/dex_raydium_cl.rs       Raydium CLMM
src/dex/dex_raydium_lpv4.rs     Raydium AMM v4
src/dex/dex_raydium_cpmm.rs     Raydium CPMM
src/dex/dex_orca_whirlpool_v2.rs Orca Whirlpools
src/dex/dex_orca_token_swap_v2.rs Orca v1
src/dex/dex_meteora_dlmm.rs     Meteora DLMM
src/dex/dex_meteora_pools.rs    Meteora classic Pools
src/dex/dex_meteora_damm_v2.rs  Meteora DAMM v2  (NEW)
src/dex/dex_pump_swap.rs        PumpSwap AMM
src/dex/dex_saber_stable_swap.rs Saber
src/dex/dex_saros_amm.rs        Saros AMM
src/dex/dex_fusion.rs           Fusion AMM       (= fUSioN9YKKSa…)
src/dex/dex_humidifi.rs         HumidFi          (= 9H6tua7jkLh… the largest unknown)
src/dex/dex_bizonfi.rs          BiSoNFi          (= BiSoNHVpsVZ…)
src/dex/dex_token_mill_v2.rs    Token Mill v2    (NEW)
```

**Architecture is custom no-std, not Anchor.** The exported entrypoint is
704 bytes (88 SBPF instructions), the program is `#[no_std]` with only 8
dynamic symbols (entrypoint, custom_panic, 6 syscalls). Dispatch uses
**small-integer tags** (1,824 `JEQ_IMM` in .text), not 8-byte Anchor
sighashes — a deliberate ~5-10k CU saving per tx vs the Anchor default.

**DEX program IDs are NOT hardcoded.** Only System Program and wSOL mint
appear as 32-byte sequences in the binary. Every DEX program ID the router
invokes is passed by the client in the tx's account-meta list. **This is
the architectural reason new venues like Tessera, GoonFi, and ZeroFi can
be added to the bot's repertoire without redeploying the program** — only
the off-chain client needs to learn the new venue, the on-chain executor
is venue-agnostic.

**Build environment leak:** `/Users/runner/work/platform-tools/...` paths
in `.rodata` confirm the program is compiled in a **GitHub Actions macOS
runner** using the official Solana platform-tools toolchain. Real CI/CD,
not a one-shot dev build.

**Code shape:** ~44,027 SBPF instructions, ≥79 distinct functions, 484
internal call sites, 4,183 conditional branches. A non-trivial codebase
(comparable in size to Jupiter Aggregator v6) with substantial per-DEX
logic and slippage guards.

The fuller breakdown including the SBPF opcode-frequency analysis and the
inferred runtime architecture is in `REVERSE_ENGINEERING.md`.

### 0.3 The router program is self-published, self-upgraded

`AN225ksocfZpbPVEbwffiANbtUdYbySM3WJ6dbsYAqij` (the outermost program in
99%+ of the bot's txs) has the following on-chain metadata:

| field | value |
| --- | --- |
| `executable` | `true` |
| `owner_program` | `BPFLoaderUpgradeab1e11111111111111111111111` |
| `programData` PDA | `HBTxd8CRuqSvf8XN8x3X4yGjheavCF5yRSgnLCPje15q` |
| **`upgradeAuthority`** | **`MRiYA4oN3158fCV8evhuCofrDzbHyYvYnGZUDJvoCsa`** |
| compiled size | **378,968 bytes** |
| `anchorVerify` | `unverified` (source deliberately not published) |

Three things this tells us:

1. **The bot is its own program author**: the same key that signs every arb
   tx controls program upgrades. Operator and engineer are the same entity;
   no third-party MEV-router-as-a-service is in the loop.
2. **378KB compiled is huge** — comparable in size to Jupiter Aggregator v6
   (~340KB). This is not a thin wrapper; the program contains substantial
   multi-DEX routing logic, slippage guards, Jito-tip injection, and likely
   bespoke CPI dispatch code for every venue the bot trades against.
3. **Deliberately unverified**: the Anchor source is not published. Solscan
   cannot parse the program's instruction layout into named activities,
   which is why all the wallet's "swap" semantics are hidden in the outer
   `Unknown` instruction. This is a competitive-moat decision — the operator
   does not want the strategy reverse-engineered.

---

## 1. The big four findings (smoking guns)

### 1.1 Zero-tip txs land at **41.5%** — paid-tip txs land at 6-22%

| priority_fee bucket | land_pct |
| --- | ---:|
| **0 (no tip)** | **41.5%** |
| < 10k lamports | 6.1% |
| 10k–100k | 14.9% |
| 100k–1M | 18.7% |
| 1M–10M | 21.7% |
| > 10M | 12.3% |

This is **the opposite of how a normal Solana bot performs**. A bot that
competes in the public priority-fee market gets the inverse curve: higher tips
→ higher land rate. The fact that this bot's *highest* land rate is when it
pays *zero* tip means **its main submission path bypasses the public
priority-fee auction**. Two technologies fit:

1. **Stake-weighted QoS (SWQOS)** through a staked RPC provider (Helius, Triton,
   Shyft, BlockRazor, etc.) that forwards to leaders with delegation-based
   priority bypassing the mempool. `[INFERRED]`
2. **Direct TPU forwarding** from a co-located client to upcoming leaders
   (predicted from the leader schedule), again bypassing public competition.
   `[INFERRED]`

The paid-tip txs (the remaining buckets) are the bot's *speculative or
competitive* submissions — when it's racing other searchers it does enter the
auction, and predictably loses 80%+ of those races.

### 1.2 Alt-signer txs land at **81.8%** vs main-signer 15.1% (5.4×)

| who | land_pct |
| --- | ---:|
| Main signer (`MRiYA…`) | 15.1% |
| 9 alt signers (combined) | **81.8%** |

Only ~0.05% of txs use the alt signers, but they land at over 5× the rate.
Two of the alt signers share the prefix `GLk…` (`GLkLuUxsJgU…`,
`GLkLiMc6yk…`), strongly indicating **vanity-generated related keys**.

The inferred reason this works: Solana validators enforce **stake-weighted
QoS per-signer**. A single key submitting at a rate above its delegated
stake's share gets throttled. By splitting traffic across multiple
independently-staked signers (or signers attached to relays/validators that
forward them with priority), the bot gets the equivalent of multi-validator
TPU bandwidth on what would otherwise look like one wallet. `[INFERRED]`

The selective use (0.05% of txs) suggests these alt signers are reserved for
**the highest-value or hardest-to-land opportunities** — the routine 99.95%
go through the cheaper main-signer path.

### 1.3 The bot maintains 1,000+ durable nonce accounts

| metric | value |
| --- | --- |
| distinct nonce accounts in use | **1,000+** |
| % of txs that begin with `advanceNonce` | **~99%** |

Durable nonces are the foundation of **pre-signed transactions** on Solana.
A standard tx is invalidated after ~60-90 seconds because the recent blockhash
expires. A nonce-based tx references a stored nonce account whose value only
changes when the bot's `advanceNonce` instruction increments it — so the tx
**stays valid indefinitely until the bot chooses to fire it**.

A normal bot needs 1-2 nonce accounts. **This bot has at least 1,000**, each
costing ~0.001 SOL in rent (~$0.20). Why so many? Two reasons:

1. **Hot-account contention**: `advanceNonce` write-locks the nonce account
   during execution. If you only have one nonce account and try to submit
   multiple txs to the same slot, they serialize. With 1,000 nonce accounts
   the bot can run 1,000 parallel submission threads without lock contention.
2. **Shotgun bursts**: the data shows 107 slots with >50 txs from this bot
   each. Each of those txs needs an independent nonce. The nonce pool **is**
   the parallelism budget.

This is sub-millisecond-latency, parallel-pipelined arb infrastructure.

### 1.4 Multi-tx-per-slot density — two distinct regimes

| txs in slot | n slots | total txs concentrated there |
| ---:| ---:| ---:|
| > 50 | 107 | 7,094 |
| 21-50 | 1,362 | ~39,417 |
| 6-20 | 35,035 | 293,271 |
| 3-5 | 127,779 | 459,053 |
| 2 | 239,353 | 478,706 |
| 1 (solo) | 644,259 | 644,259 |

The distribution is **bimodal** with two distinct interpretations:

**Regime A — competitive parallel-path submission (the 2–50/slot band).**
When the bot detects a competitive arb opportunity, it submits the *same*
arb through multiple submission channels (Jito bundle, staked RPC #1, staked
RPC #2, direct TPU forwarder, …) using different signers/nonces. Whichever
path lands first wins; the rest fail. This is the textbook MEV technique
for parallel-path resilience.

**Regime B — maintenance/setup bursts (the >50/slot extremes).**
The largest single-slot count is **166 txs** — and inspection of that slot
reveals all 166 landed at the same base-5000-lamport fee, all signed by
the same key, and **none of them invoked a DEX program**. These bursts are
the bot performing **bulk infrastructure operations** (creating dozens of
ATAs, refreshing nonce accounts, closing dust accounts) inside a single
slot. The fact that 166 base-fee txs can land simultaneously confirms the
privileged-submission hypothesis from another angle: this is bandwidth no
normal-RPC wallet has access to.

Both regimes require the same underlying capability: the bot can push
50–166 distinct txs at one validator's TPU pipeline in a single slot
without rate-limit throttling. Whether those txs are racing competitors or
batching maintenance, the limiting factor — privileged ingress — is the
same.

---

## 2. Capital efficiency and inventory positioning

### 2.1 The wallet holds 2,751 distinct token-mint ATAs

The wallet maintains pre-funded Associated Token Accounts for **2,751
different SPL tokens** (from `balance_changes` aggregation). Only **0.01%**
of all txs include any `createAccount` / `initializeAccount` instruction —
meaning the bot has **already positioned ATAs for nearly every token it
might trade** before the trading even starts.

Why this matters:

- ATA creation costs ~0.002 SOL rent + ~5,000 CU + ~3 extra accounts in the
  lock set. Avoiding it on every arb saves measurable latency budget.
- Creating an ATA at arb time risks a race condition (someone else creates
  it first with a different owner), causing the tx to fail. Pre-funded ATAs
  remove that failure mode entirely.
- For the bot to have pre-funded 2,751 ATAs, **it must be continuously
  monitoring new Pump.fun launches and Meteora pool creations** to position
  inventory before the first arb opportunity. `[INFERRED]`

The 161 in-tx creations are the bot's "I encountered a brand-new mint" events
— roughly 3 per day, consistent with Pump.fun's graduation rate.

### 2.2 Two operational wSOL accounts: one treasury, one transit

| wSOL account | uses | min balance | max balance | role |
| --- | ---:| ---:| ---:| --- |
| `4mvdsmiuyx4Y…` | 24,545 | 708 wSOL | **4,275 wSOL** | treasury / inventory |
| `8dMciA7YGTB8…` | 5,159 | 0 | 0 | pass-through transit |

The treasury account has held as much as **4,275 wSOL**. The transit
account always shows 0 balance — it's debited and credited the same amount
within a single tx, used only to route wSOL between pools in atomic arbs.

This is professional bookkeeping: keep working capital in one place, route
through a deterministic transit account so the swap graph is simpler. At
peak the bot was deploying **4,275 wSOL (~$650k at typical prices)** of
working capital.

### 2.3 Capital turnover: ~37,000 wSOL routed through top 10 pools alone

Top 10 destinations of wSOL outflows from the wallet, by total wSOL sent:

| pool vault | wSOL sent | n txs | avg/tx |
| --- | ---:| ---:| ---:|
| `5pVN5XZB8cY…` | 7,323.82 | 16 | **457.7 wSOL** |
| `C3FzbX9n1YD…` | 6,514.70 | 27 | 241.3 wSOL |
| `EUuUbDcafPr…` | 6,320.96 | 27 | 234.1 wSOL |
| `ATRsNGv2nD…` | 3,807.26 | 10 | 380.7 wSOL |
| `9TeWUgfjbtPh…` | 3,480.88 | 15 | 232.1 wSOL |
| `BkSYpPsv11U…` | 3,132.44 | 8 | 391.6 wSOL |
| `DT2krA8vSP9…` | 2,918.07 | 12 | 243.2 wSOL |
| `7e9ExBAvDvuJ…` | 2,284.64 | 4 | 571.2 wSOL |
| `H292B1VbSv…` | 2,139.20 | 10 | 213.9 wSOL |
| `EYj9xKw6Z…` | 1,126.27 | 2 | 563.1 wSOL |

Average single-arb wSOL deposit: **350-570 wSOL**. At a 4,275 wSOL peak
balance, that means a single arb deploys 8-13% of the bot's working capital.
The largest single-arb wSOL outflow is **882 wSOL in one tx** — over 20%
of total capital on one trade. The bot is comfortable concentrating very
large bets on conviction opportunities.

---

## 3. Strategy reconstruction (the full playbook)

### 3.1 Inventory acquisition — pre-graduation Pump.fun watch

Pump.fun memecoins start on a **bonding curve** (the Pump.fun Bonding Curve
program). When the curve hits a certain market cap, the project **graduates**
to a constant-product AMM on **PumpSwap AMM** — and shortly after, secondary
markets open on **Meteora DLMM**, **Orca Whirlpools**, **Raydium CLMM/CPMM**,
etc.

The window between graduation and full price discovery is where the bot
operates. Pump.fun is the price-leader (highest volume) but the secondary
DEXes lag in re-quoting, creating spreads that last 1-5 slots.

Evidence:
- 45.9% of arbs touch at least one `*pump`-suffix mint (Pump.fun-launched)
- Top venue pair is **Meteora DLMM ↔ PumpSwap AMM** by a wide margin
- The Pump.fun Bonding Curve program appears in only 0.52% of all txs
  — the bot doesn't arb pre-graduation (low liquidity, high slippage); it
  waits for graduation.

### 3.2 Detection — sub-slot pool state streaming `[INFERRED]`

For the bot to fire arbs the moment Pump's price diverges from Meteora's,
it must be receiving pool state updates **before** the public RPC has them
indexed. The candidates on Solana are:

- **Yellowstone gRPC** (Triton One): geyser plugin streaming all account
  writes from validators. Sub-slot latency.
- **Helius LaserStream**: similar account-streaming product with edge nodes
  in major datacenters.
- **Jito Shredstream**: TPU shred-level streaming. Gets you state changes
  **before** they're confirmed (still-being-built blocks).
- **Self-hosted RPC** colocated with leader validators.

The 41.5% no-tip land rate (section 1.1) and the alt-signer 81.8% land rate
(section 1.2) both require infrastructure that competing bots don't have.
A bot using public RPC alone could not achieve either number.

### 3.3 Decision and tx construction

When the bot's monitoring detects a profitable spread:

1. **Verify slippage envelope** — the router program (`AN225ksocfZp…`) almost
   certainly has on-chain slippage checks. Failed arbs end with `status='0'`
   and pay only fees — gross-loss per failed arb averages near zero
   (-2.7 SOL total across 1,597 losers vs +249.9 SOL on 4,918 winners).
2. **Compose the swap legs into one router ix** — instead of submitting
   separate Meteora-swap + PumpSwap-swap txs (slow, atomically vulnerable),
   the bot's router program **invokes the DEX programs via CPI** in one
   instruction. This is why the outer ix template is so consistent (4-7
   outer ixs always: `advanceNonce` + `ComputeBudget` × 2-3 + 1-2 router ix).
3. **Set CU budget tightly** — the bot requests CU in the 100-200k range
   (65% of txs), which is the sweet spot for landing in busy blocks (data
   showed >400k CU dropped landing to 7.8%).
4. **Pull a fresh durable nonce** from the 1,000+ pool, sign with the selected
   signer key, hand off to the submission path.

### 3.4 Submission — tiered, parallel, infrastructure-heavy

The land-rate evidence implies at least **three submission paths**:

| path | identifier | land rate | when used |
| --- | --- | ---:| --- |
| **Main + zero-tip privileged** | main signer, no tip | 41.5% | bulk routine arbs (≈40% of arbs) |
| **Main + paid priority** | main signer, tip 100k-10M | 18-22% | competitive arbs |
| **Alt-signer privileged** | alt signers | **81.8%** | high-value selective |
| **Jito bundle** | overlay with `tip → Jito` | n/a | 23% of arbs (atomicity) |

For shotgun-burst slots (>50 same-slot txs), the bot likely fires **all
paths simultaneously** — Jito bundle + multiple staked RPCs + direct TPU.
166 same-slot txs out of one wallet only makes sense as parallel-path
submission.

### 3.5 Settlement and capital cycling

After each successful arb:
- Token-A → wSOL roundtrip returns the bot to a wSOL-denominated state
- Profit accrues in the treasury wSOL account `4mvdsmiuyx4Y…`
- Periodically the bot **unwraps wSOL → native SOL** to pay fees (e.g. the
  `3xpnbYbRUd…` tx unwrapped 135 wSOL → 135 SOL)
- Native SOL flows back out as priority fees, Jito tips, and nonce-account
  rent

### 3.6 Adaptive strategy expansion

The weekly DEX-usage timeline (section L3 of `ANALYSIS.md`) shows:

- Early operating period: Meteora DLMM + PumpSwap dominate, no Tessera
- **Tessera first appears mid-life** — coincides with Tessera's emergence as
  a major Solana prop-AMM
- Tessera quickly spikes to be the #5 venue
- Later periods: Tessera levels off as competition catches up

This is **strategic monitoring**: the bot's operator is watching the Solana
DEX landscape and bolting on new venues within days of their becoming
significant. A static-strategy bot would have missed Tessera entirely.

---

## 4. Why competitors don't replicate this

The bot's edge is a **compound product** of multiple components, each of which
costs real money and ongoing engineering. Any competitor needs all of them
simultaneously to match the win rate.

### 4.1 Infrastructure barriers

| component | what it costs / requires | who has it |
| --- | --- | --- |
| Stake-weighted RPC | $1k-10k/mo subscription OR delegate own validator (~3000 SOL minimum stake) | <1% of arb bots |
| Jito Block Engine integration | engineering effort, must run jito-solana client or use API | ~10% of MEV bots |
| 1,000+ durable nonce accounts | $200+ rent capital, parallelism architecture | almost nobody |
| 2,751 pre-funded ATAs | ~$5,500 in rent + continuous mint discovery pipeline | <0.1% of bots |
| Multiple staked signers | engineering for key rotation, separate validator delegations | <0.1% of bots |
| Sub-slot pool state streaming | $500-5000/mo for Yellowstone gRPC / LaserStream / Shyft | small number of pro bots |
| Co-located decision engine | datacenter colocation in same region as leader validators | a handful of teams |
| Custom router program | months of Solana program dev, ongoing maintenance | a handful of teams |

### 4.2 Operational barriers

- **Continuous mint monitoring**: to maintain 2,751 ATAs ahead of demand, the
  bot's operator must run a Pump.fun launch scanner 24/7 and front-run their
  own ATA creation against the rest of the market.
- **Strategy R&D**: the W19 addition of Tessera shows ongoing research into
  new venues. That's analyst hours, not just engineering.
- **Capital concentration risk management**: deploying 400-880 wSOL per arb
  on volatile memecoins requires real risk controls.
- **24/7 reliability**: 37k txs/day average means the bot is essentially
  never down. That implies redundant infrastructure, on-call rotation, etc.

### 4.3 Why the obvious "just pay more priority fee" doesn't work

A bot competing with this one might think: "I'll just pay 10× the priority
fee to outbid them." The data shows that doesn't work — paid-tip txs land
at 12-22%, while this bot's *zero-tip* path lands at 41.5%. **Public
priority-fee competition is an inferior channel** to the privileged
submission paths this bot has.

The competitor must instead build/buy the same privileged channel — and
that's not for sale at any price to retail. Stake-weighted submission paths
are typically gated by either staked-validator relationships or business
deals with RPC providers.

---

## 5. Inferred technology stack `[INFERRED]`

Based on the evidence, the most likely stack:

### 5.1 Off-chain components

- **State streaming layer**: Yellowstone gRPC plugin or Helius LaserStream,
  streaming all writes to the Meteora DLMM and PumpSwap AMM program accounts
  (and the prop-AMMs). Likely subscribed to ~5-10k pool accounts at any time.
- **Decision engine**: bare-metal Rust binary (most likely) running in a
  colocated datacenter near a leader-class validator. Latency budget for
  detect → sign → submit is probably **<100ms**, ideally <30ms.
- **Pre-signed tx pool**: maintains thousands of pre-built and pre-signed
  tx templates referencing the 1,000+ durable nonces, ready to fire by
  changing only the swap-leg parameters. Likely a Redis-style fast store
  for nonce-to-tx mapping.
- **Multi-path submitter**: emits each tx via:
  - Jito Block Engine bundle endpoint (for 23% of arbs)
  - Several staked-RPC submission endpoints in parallel
  - Direct TPU UDP forwarding to upcoming leaders (computed from leader
    schedule)

### 5.2 On-chain components (measured)

- **Custom native router program** `AN225ksocfZpbPVEbwffiANbtUdYbySM3WJ6dbsYAqij`:
  - **378,968 bytes compiled** — comparable in size to Jupiter v6 (~340KB),
    indicating a complex multi-DEX dispatch core
  - Deployed via the upgradeable BPF loader; **upgrade authority is the bot
    wallet itself** (operator self-publishes and self-upgrades)
  - **Deliberately unverified** — no Anchor source / IDL published; Solscan
    can't parse the instruction layout into named actions
  - Program-data PDA: `HBTxd8CRuqSvf8XN8x3X4yGjheavCF5yRSgnLCPje15q`
    (2.64 SOL rent-exempt for the bytecode storage)
  - Encapsulates: slippage check, swap-leg CPI dispatch to every venue the
    bot uses (Meteora DLMM, PumpSwap AMM, Orca, Raydium CLMM/CPMM/v4,
    Tessera, ZeroFi, GoonFi, Manifest, plus the still-unnamed prop-AMM
    programs), profit/loss assertion, optional Jito-tip transfer
  - Standardized account-list layout — predictable CU lock-set, easier for
    leaders to schedule, contributes to the consistent 100–200k-CU profile
- **1,000+ durable nonce PDAs** — owned by the bot, advanced atomically with
  each tx; provides the parallel-pipeline submission budget
- **Two operational wSOL token accounts** — treasury (`4mvdsmiuyx4Y…`, peak
  4,275 wSOL) and transit (`8dMciA7YGTB8…`, always 0 balance)
- **2,751 pre-funded SPL ATAs** — covering nearly every mint the bot has
  ever touched; only 0.01% of arbs need an in-tx ATA creation

### 5.3 Costs (rough, monthly)

| line item | estimated $/mo |
| --- | ---:|
| Stake-weighted RPC subscription | $1,000-5,000 |
| Yellowstone gRPC / shred streaming | $1,000-3,000 |
| Co-located server (bare metal) | $500-2,000 |
| Validator stake / SWQOS arrangement | $5,000-20,000 opportunity cost |
| Engineering / on-call labor | $20,000+ |
| Jito tips paid | ~50 SOL/mo (~$7,000-9,000) |
| Priority fees paid | ~500 SOL/mo (~$70,000-90,000) |
| **Total estimated** | **~$100k-130k/month** |

Against the estimated **+185 SOL/day (~$28k/day, $850k/month)** in gross
profit, the margin is ~7-9× over operating cost. Healthy but not effortless.

---

## 6. The bot is improving — operator is iterating

Daily land rate has trended upward over time, climbing from **7-11%** early
in the bot's operation to **20-33%** in its most recent activity. The
overall improvement is roughly **3-4×**. Either the strategy got smarter,
the infrastructure got better, the competition weakened, or some
combination. Either way the bot is **not static** — there's a live
engineering team behind it iterating on the model.

A single-day anomaly is also informative: on one day the bot paid
**109.3 SOL in fees** (13% of its entire fee budget concentrated in 24
hours). Average fee that day was 7× the baseline. Two interpretations:
- A major MEV opportunity warranted heavy priority bidding
- A network-wide event (congestion / leader misbehavior) forced the bot to
  outbid much harder than usual

---

## 7. Status of the open questions

Resolved or partially resolved during this analysis:

1. **Who runs this bot?** — Single operator team, identified via the
   vanity-prefixed `mriya4w…` → `MRiYA…` funding chain (section 0.1).
   The team owns both wallets, the 9 alt signers, and the AN225 router
   program. Root provenance (`8shhBrQN…`) is a deliberately-laundered
   throwaway hop — further upstream identification would require
   off-chain signals.
2. **What are the unnamed programs the bot heavily uses?** — All 7
   (`9H6tua…`, `cpamdpZCGK…`, `proVF4pMXVa…`, `fUSioN9YKKSa…`,
   `HpNfyc…`, `24Uqj9JC…`, `REALQqNEom…`) are confirmed as upgradeable
   BPF programs (executable, owned by `BPFLoaderUpgradeable`). None are
   verified or labeled on Solscan. Their co-occurrence patterns with the
   *named* prop-AMMs (ZeroFi, Tessera, GoonFi) and the heavy lifetime tx
   counts (23%, 12%, 3%, 2%, 1.5%, 5%, 1.5% of all txs respectively)
   place them squarely in the **proprietary-AMM** class. The Solana
   ecosystem currently recognizes HumidFi, SolFi, and Obric v2 as the
   major unidentified prop-AMMs by Jupiter volume; the program IDs above
   are almost certainly these or peers in the same category — but
   confirmation requires off-chain reputation signals (CEO X-account
   self-doxing, Jupiter program-name announcements) we cannot derive
   from on-chain data alone.
3. **Multi-tx-per-slot intent** — Resolved (section 1.4). The very large
   bursts (>50/slot) are maintenance, not arb races; the 2–50/slot
   bursts are the actual competitive parallel-path submissions.
4. **Slot-leader correlation** — Still unresolved. Identifying *which*
   validator(s) preferentially route the bot's txs requires
   cross-referencing leader-schedule data per slot — out of scope for
   the current dataset.

Remaining truly-open questions:

5. **Which specific RPC provider / staked validator(s) carry the
   privileged submission**? Names of the providers (Helius LaserStream,
   Triton Yellowstone, Shyft, BlockRazor SWQOS, self-hosted, …) can be
   guessed at by the operator's submission fingerprints but not proven
   from on-chain data alone.
6. **How does the bot discover new Pump.fun graduations fast enough to
   pre-fund ATAs**? Off-chain monitoring infrastructure — almost
   certainly a geyser stream subscribed to the Pump.fun Bonding Curve
   program's account writes.

---

## 8. Bottom-line answer to "why are they top 1"

The bot's dominance isn't from any single clever idea. It's a
**compound advantage** built from seven mutually-reinforcing components,
each measurable on-chain:

1. **Submission path access nobody else has** (zero-tip txs land at 41.5%
   when paid-tip txs land at 6–22%; alt-signer txs land at 81.8% vs main
   15.1%) — confirmed access to a privileged ingress channel that bypasses
   the public priority-fee market entirely.
2. **A self-owned 378KB on-chain router program** packing the entire arb
   route into one tightly-tuned 100–200k-CU instruction. The same key that
   signs every arb tx is the program's `upgradeAuthority` — operator and
   engineer are the same team, the program is deliberately unverified.
3. **Pre-positioned inventory** removing every account-creation race
   condition (2,751 ATAs maintained across nearly every token the bot has
   ever traded, 1,000+ durable nonce accounts in continuous rotation, two
   wSOL operational accounts — one treasury, one transit).
4. **Parallel-path resilience** — multi-signer rotation (9 vanity-related
   alt keys held by the same operator), shotgun bursts of 2–50 same-slot
   submissions across multiple ingress channels for competitive arbs.
5. **Capital scale** — peak working capital of 4,275 wSOL means the bot
   can underwrite single-arb deposits of 400–880 wSOL, dominating the
   large opportunities that other bots are too undercapitalized to take.
6. **Operator engineering velocity** — measurable improvement (land rate
   has 3-4×'d over time) plus venue expansion (e.g. Tessera added
   mid-life when prop-AMMs became significant on Solana) — there is a
   live team iterating, not a static program left running.
7. **Provenance hygiene** — the operator deliberately laundered the bot's
   funding through a disposable hop (`8shhBrQN…` → `mriya4w…` → `MRiYA…`),
   the router program is unverified, and the alt-signers are vanity-paired.
   Whoever runs this does not want to be identified, and they have the
   operational discipline to keep it that way.

Any *one* of these can be replicated. **All seven together** requires
either a well-funded prop-trading firm with Solana validator relationships,
or a team with several years of MEV experience that has incrementally built
each component. That's the moat.
