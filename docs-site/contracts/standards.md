---
title: Reference standards
description: STS-20 tokens, STL-DNS names, the constant-product liquidity pool and Account Object sessions — layouts, entry points, events and documented audit caveats.
---

# Reference standards

Four contracts in `stellereum-contracts/contracts/` demonstrate the patterns the runtime supports.
They share a status line you must take literally:

> **STATUS: DEMO-GRADE … DO NOT deploy with value without a full audit.**

They are useful as schemas and as test fixtures. They are not audited products, they use integer
account ids rather than 32-byte addresses in their public arguments, and several of their own
headers call out residual gaps. It documents what the code does, including where that differs from an aspirational feature list.

## Shared conventions

All four contracts:

- are `#![no_std]`, export `#[no_mangle] pub extern "C" fn …`, and install
  `setup_wasm_panic_handler!()`;
- pack multiple parameters into one `i64` because they predate the typed ABI;
- authenticate value-moving entry points with `caller_is(id)`, the canonical binding of an integer
  id to `host.caller`;
- return `SUCCESS = 0` / negative `ERR_*` codes for expected failures, and `panic!` for impossible
  states;
- emit integer `(topic, value)` events; the topic numbers are contract-local constants.

::: danger Integer ids are public
An id is not a secret and not an address. `caller_is(id)` is the only thing that makes an id
meaningful for authorization. A contract that accepts `from`/`owner` and does not bind it to
`host.caller` is trivially drained. Every value-moving method below does bind it; your fork must
keep that property.
:::

## Comparison

| Contract | Purpose | Auth model | Moves native value? | Main residual risk |
| --- | --- | --- | --- | --- |
| STS-20 | fungible token | `caller_is(owner/spender/admin)` | no | slot-space collisions, integer ids |
| STL-DNS | name registry + auctions | owner/treasury bound for transfer/target; auctions permissionless | **no** | no auction clock, no escrow |
| Liquidity Pool | constant-product AMM accounting | depositor/withdrawer bound; swaps permissionless | **no** | no slippage parameter, no token transfers |
| Account Object | account abstraction, sessions, recovery | owner/guardian bound; sessions bearer-style | no | caller-supplied time, bearer sessions |

## STS-20 — fungible token

**Purpose.** An ERC-20-shaped token with a 50 bps protocol fee, a treasury leg, a burn-to-zero
path, allowances and mint/burn restricted to the admin account.

### Storage layout

| Slot | Meaning |
| --- | --- |
| `0` | total supply |
| `1` | initialized flag |
| `2` | admin account id (default `1`) |
| `3` | treasury account id (default `99`) |
| `1_000_000 + id` | balance of account `id` |
| `10_000_000 + (FNV-1a(owner ‖ spender) & 0x0FFF_FFFF)` | allowance |

`allowance_slot` hashes the two ids with 64-bit FNV-1a and keeps 28 bits, then adds the allowance
offset. Balances use a direct offset.

::: warning Balance and allowance ranges can overlap
`balance_slot(id) = 1_000_000 + id` for any positive `id`, while allowances live at
`10_000_000 + hash28`. An account id around nine million would land in the allowance region. The
reference contract constrains `to < 1_000` but not `from`; a production token should bound ids
(e.g. `< 1_000_000`) or use a hashed layout for both maps.
:::

### Entry points

| Method | Packing / argument | Authorization | Result |
| --- | --- | --- | --- |
| `init(supply)` | `supply > 0` | none; panics if already initialized | mints supply to admin `1`, emits Mint |
| `decimals(_)` | any | none | `9` |
| `total_supply(_)` | any | none | supply |
| `balance_of(id)` | `id > 0` | none | balance or `0` |
| `allowance(packed)` | `owner × 1_000_000 + spender` | none | remaining allowance |
| `approve(packed)` | `owner × 10_000_000_000 + spender × 100_000 + amount` | `caller_is(owner)` | sets the allowance to `amount` |
| `transfer(packed)` | `from × 100_000_000 + to × 100_000 + amount` | `caller_is(from)` | moves `amount`, fee to treasury |
| `transfer_from(packed)` | `spender × 100_000_000_000 + from × 10_000_000 + to × 100_000 + amount` | `caller_is(spender)` + allowance ≥ amount | spends allowance, moves tokens |
| `mint(arg)` | `amount`, or `admin_id × 10_000_000_000 + amount` | `admin_id == stored admin` **and** `caller_is(admin)` | increases supply and admin balance |
| `burn(arg)` | same shape as mint | same | decreases supply and admin balance |

Ranges enforced by `transfer` / `transfer_from`: `from > 0`, `0 ≤ to < 1_000`, `0 < amount <
100_000`. `transfer_from` validates these **before** touching the allowance (an earlier version
burned the grant on invalid input).

### Economics

- **Fee:** `ceil(amount × 50 / 10_000)` — ceiling division prevents zero-fee evasion on tiny
  amounts. `net = amount - fee`.
- **Dust refusal:** if `net <= 0` the transfer returns `ERR_INVALID_ARGUMENT` and moves nothing.
  A 1-unit transfer would otherwise debit the sender and credit nothing.
- **Burn:** `to == 0` is a direct, untaxed burn. It debits the sender, reduces total supply, and
  emits Burn. Account `0` is the black hole.
- **Treasury:** the fee is credited to the stored treasury id (default `99`).
- **Overflow:** `checked_add` on recipient/treasury/supply; failure returns `ERR_OVERFLOW`
  instead of trapping.

### Allowances: overwrite, not increment

`approve` stores an **absolute** value. This avoids the classic ERC-20 `approve`/`increaseAllowance`
race where an increment can be front-run. It does not make an old approval un-replayable: a
previously signed approve can land later and overwrite a newer one. The transaction nonce is the
replay guard; treat each approve as a full replacement, and set it to `0` before setting a new
value if your client cannot guarantee ordering.

### Events

| Topic | Constant | Value |
| --- | --- | --- |
| `2001` | `TOPIC_TRANSFER` | transfer amount |
| `2002` | `TOPIC_MINT` | minted amount |
| `2003` | `TOPIC_BURN` | burned amount |
| `2004` | `TOPIC_APPROVAL` | approved amount |

The event carries the amount only; the counterparties are not encoded. Indexers must derive them
from the call arguments.

### Audit-lite caveats

- Demo-grade; integer ids; no privacy; no per-account nonce inside the contract.
- `init` is permissionless: the first caller initializes the token, but the admin is the hard-coded
  id `1`, so only the address that canonicalizes to id 1 can mint/burn. On a real deployment that
  identity must be planned, not assumed.
- `from` is not bounded, so balance slots can drift into the allowance region (see above).
- The 28-bit allowance hash is not collision-free.
- `approve` cannot express "increase by"; clients must read the current value and send an absolute
  replacement.
- No pause, no blacklist, no upgrade hook in the contract. The registry's engine-level pause (not
  exposed over RPC) would stop all calls and cannot be undone.

## STL-DNS — name registry and auctions

**Purpose.** A `.stl` name registry with TON-style length pricing, reserved protocol names, a
permissionless auction state machine and an independent resolution target.

### Storage layout

Globals:

| Slot | Meaning |
| --- | --- |
| `0` | treasury account id |
| `1` | registered domain count |
| `2` | initialized flag |

Per domain: `base = 1_000 + domain_id × 10`.

| Offset | Meaning |
| --- | --- |
| `+0` | state: `0` available, `1` auction, `2` registered |
| `+1` | owner / highest bidder |
| `+2` | highest bid |
| `+3` | reserved flag: `0` normal, `1` system burn, `2` protocol reserved |
| `+4` | resolution target |

`domain_id` is computed off-chain by the SDK's `hash_domain(name)`: FNV-1a over the name, masked to
28 positive bits, with `0` mapped to `1`. The contract never sees the name string.

### Price grid

| Name length | Minimum bid (STELL) |
| --- | --- |
| 4 | 200 |
| 5 | 75 |
| 6 | 50 |
| 7 | 25 |
| 8 | 20 |
| 9 | 15 |
| 10 | 10 |
| 11–126 | 5 |
| < 4 or > 126 | `-1` (refused) |

### State machine

```text
available ──start_auction──▶ auction ──place_bid (+10%)──▶ auction
                                  │
                                  └──finalize_auction──▶ registered
registered ──set_target──▶ registered (target changed)
registered ──transfer────▶ registered (owner + target changed)
```

- `start_auction` requires state `available`, a non-reserved domain, and a valid length. It records
  the bidder as owner and the minimum bid as the current bid.
- `place_bid` requires state `auction`; the new bid is `current + max(current / 10, 1)`, i.e. a
  minimum 10% raise. The `step` field in the packed argument is parsed but **ignored**.
- `finalize_auction` requires state `auction`, sets state `registered`, increments the domain count,
  and emits Finalized. It is **permissionless and immediate**.
- `resolve` returns `0` for unregistered, unfinalized, or system-burn domains; otherwise the target
  if set, else the owner.
- `set_target` and `transfer` require the caller to be the owner (or treasury for a protocol-reserved
  domain) **and** `caller_is(that id)`.

### Entry points

| Method | Packing | Notes |
| --- | --- | --- |
| `init(treasury)` | `treasury > 0` | registers burn/trash to `0` and 12 protocol names to treasury |
| `get_min_bid(len)` | length | price grid; `-1` for invalid |
| `get_hue(id)` | domain id | `(id × 137) % 360` for NFT card color |
| `start_auction(packed)` | `id × 10_000_000_000 + bidder × 100_000 + len` | panics on reserved/invalid |
| `place_bid(packed)` | `id × 10_000_000_000 + bidder × 10_000 + step` | step ignored |
| `finalize_auction(id)` | id | immediate, anyone may call |
| `resolve(id)` | id | `0` = no resolution |
| `set_target(packed)` | `id × 10_000_000_000 + caller × 100_000 + target` | target must be `< 100_000` |
| `transfer(packed)` | `id × 10_000_000_000 + caller × 100_000 + new_owner` | `new_owner > 0` and `< 100_000`; also resets target |

### Events

| Topic | Event | Value |
| --- | --- | --- |
| `30` | auction started | domain id |
| `32` | bid placed | domain id |
| `33` | auction finalized | domain id |
| `34` | target updated | new target |
| `35` | domain transferred | domain id |

### Audit-lite caveats

::: danger There is no auction clock or anti-snipe extension
The contract stores no deadline and has no "bid in the last N minutes extends the auction" rule.
`finalize_auction` succeeds as soon as the state is `auction`, by anyone, at any time. A bidder can
be outbid and the auction finalized in the same block by a third party. Do not describe or use this
as snipe-resistant without adding a deadline + extension mechanism first.
:::

- **No funds move.** The header says auction mechanics "move no funds and stay permissionless".
  There is no escrow, no bid deposit, no settlement and no refund. The `highest bid` is a number in
  storage. A production auction must add escrow and payout.
- **Bidders are not authenticated.** `start_auction`/`place_bid` accept any `bidder_id`; that is
  consistent with a permissionless auction, but it means a third party can open or bid on behalf of
  an id. Only `transfer`/`set_target` enforce `caller_is`.
- **The name is not stored or verified.** The caller supplies both `domain_id` and `name_len`; the
  contract cannot check that the length matches the hashed name. Clients must compute both
  consistently.
- `domain_id` is a 28-bit hash, so collisions are possible and are not detected.
- The resolution target is limited to `< 100_000` by the packing, while ownership ids can be larger;
  a large owner id cannot be expressed as a target in `set_target`.
- `init` is permissionless; the first caller chooses the treasury.

## Liquidity Pool — constant product

**Purpose.** A constant-product (`x × y = k`) AMM with LP shares, a fee in basis points, and
integer quotes computed in `u128`.

### Storage layout

| Slot | Meaning |
| --- | --- |
| `0` | initialized flag |
| `1` | total LP shares |
| `2` | reserve A |
| `3` | reserve B |
| `4` | fee in basis points |
| `10_000 + user_id` | user's LP shares |

### Entry points

| Method | Packing / argument | Authorization |
| --- | --- | --- |
| `init(fee_bps)` | `0 ≤ fee < 10_000` | none; one-shot |
| `get_reserve_a/b(_)` | any | none |
| `get_total_shares(_)` | any | none |
| `shares_of(id)` | id | none |
| `deposit(packed)` | `user × 10_000_000_000 + amount_a × 100_000 + amount_b` | `caller_is(user)` |
| `withdraw(packed)` | `user × 1_000_000 + shares` | `caller_is(user)` |
| `swap_quote(dx)` | input amount | none |
| `swap_quote_b_for_a(dy)` | input amount | none |
| `swap_a_for_b(dx)` | input amount | **none** (permissionless) |
| `swap_b_for_a(dy)` | input amount | **none** |

### Math

- **First deposit:** shares = `(amount_a + amount_b) / 2`.
- **Later deposits:** `share_a = amount_a × total_shares / reserve_a`, likewise for B, and the
  minted amount is `min(share_a, share_b)`. Taking the minimum keeps the deposit from diluting
  existing holders when the ratio is off.
- **Withdraw:** `payout = shares × reserve / total_shares`, floored, for each leg.
- **Quote A→B:** `dy = y × dx × (10_000 - fee) / (x × 10_000 + dx × (10_000 - fee))`.
- **Quote B→A:** symmetric.
- **Fee:** remains in the pool, so `k` grows monotonically across swaps.

All intermediate products use `u128`, which avoids overflow for `i64`-sized reserves and inputs.
Final results are cast back to `i64`; checked arithmetic guards every reserve update.

### Events

| Topic | Event | Value |
| --- | --- | --- |
| `10` | deposit | minted shares |
| `11` | withdraw | payout A |
| `12` | swap A→B | output amount |
| `13` | swap B→A | output amount |

### Audit-lite caveats

::: danger This contract does not move tokens
`deposit`, `withdraw` and the swaps only update integer reserves and shares. They do not call an
STS-20 contract or `send_message`, and they do not verify that any token arrived. It is an AMM
**accounting model**, not a live pool. Wiring it to real assets requires a token transfer (or
outbound message) in the same call, plus reentrancy/ordering analysis.
:::

- **No on-chain slippage protection.** The header mentions slippage protection, but the swap entry
  points take only `dx`/`dy`; there is no `min_out` and no deadline. A sandwich attacker can move
  the reserve before the transaction lands and the trader accepts the new quote. Clients must
  simulate and enforce limits off-chain, or a production fork must add `min_out`/`deadline`.
- **No minimum-liquidity lock and no donation guard.** The first depositor sets the share price;
  a later donation to the reserves raises it and can round small deposits to zero. Deposit refuses
  zero shares (`ERR_INVALID_ARGUMENT`), but that protects only against complete loss, not against
  value loss from rounding.
- **Packing caps:** `amount_a`/`amount_b` must be `< 100_000`, `shares` in a withdraw must be
  `< 1_000_000`, and user ids are bounded by the multipliers.
- Swaps are permissionless by design (there is no victim to authenticate), but they also do not
  authenticate the input owner — in a real pool the input transfer is the authorization.
- `withdraw` refuses dust payouts: if a non-empty reserve would pay `0`, it returns
  `ERR_INVALID_ARGUMENT` and leaves shares/reserves untouched.

## Account Object — account abstraction

**Purpose.** A smart account with an owner, a guardian-based 72-hour social recovery, a rental
(tenant) mechanism, and session keys with spend budgets.

### Storage layout

| Slot | Meaning |
| --- | --- |
| `0` | initialized |
| `1` | owner id |
| `2` | guardian id |
| `3` | pending owner |
| `4` | anti-spam fee (stored constant `2_000_000_000`) |
| `5` | session count |
| `6` | tenant id |
| `7` | rental deadline |
| `8` | rental price |
| `9` | recovery timestamp |

Sessions: `base = 10_000 + session_id × 16`.

| Offset | Meaning |
| --- | --- |
| `+0` | service id |
| `+1` | session id (existence marker) |
| `+2` | permissions (`255`) |
| `+3` | per-session fee constant (`2_000_000_000`) |
| `+4` | budget |
| `+5` | spent |
| `+6` | revoked tombstone (`1` = terminal) |

### Entry points

| Method | Packing / argument | Authorization |
| --- | --- | --- |
| `init(owner)` | owner > 0 | none; one-shot |
| `get_owner/get_guardian/get_pending_owner(_)` | any | none |
| `transfer_ownership(packed)` | `caller × 10_000_000_000 + new_owner` | owner + `caller_is` |
| `rotate_guardian(packed)` | `caller × 10_000_000_000 + new_guardian` | owner + `caller_is` |
| `initiate_recovery(packed)` | `guardian × 10_000_000_000 + new_owner` | guardian + `caller_is` |
| `cancel_recovery(caller)` | caller id | owner + `caller_is` |
| `finalize_recovery(now)` | caller-supplied timestamp | **none** |
| `set_tenant(packed)` | `owner × 10_000_000_000 + tenant × 10_000 + hours` | owner + `caller_is` |
| `revoke_rental(caller)` | caller id | owner + `caller_is` |
| `get_active_tenant(now)` / `is_rental_active(now)` | timestamp | none |
| `create_session(packed)` | `session_id × 10_000_000_000 + service × 100_000 + budget` | **none** |
| `update_session_budget(packed)` | `session_id × 10_000_000_000 + new_budget` | **none** |
| `spend_with_session(packed)` | `session_id × 1_000_000 + amount` | **none** |
| `revoke_session(id)` | id | **none** |
| `is_session_active(id)` / `get_session_budget(id)` | id | none |

### Recovery and rental

- `initiate_recovery` requires the caller to be the stored guardian **and** `caller_is(guardian)`.
  It stores the pending owner and a recovery timestamp.
- `finalize_recovery` succeeds if `now_timestamp ≥ init_time + 259_200` (72 hours), then transfers
  ownership and clears pending/recovery/rental state.
- An owner can veto with `cancel_recovery`.
- Rentals set a tenant and a deadline of `now + hours × 3600`, with `0 < hours ≤ 8_760`.

### Sessions

- `create_session` requires `1 ≤ session_id ≤ 1_000_000`, `service < 100_000`,
  `0 < budget < 100_000`, and no existing/tombstoned session. It writes a fixed permission byte and
  fee constant.
- `update_session_budget` may only **decrease** the budget (anti-inflation), and cannot go below
  already-spent.
- `spend_with_session` adds the amount to `spent`, refuses if it would exceed `budget`, and returns
  the remaining budget.
- `revoke_session` writes a terminal tombstone; a revoked session can never be recreated.

### Events

| Topic | Event |
| --- | --- |
| `20` | account created |
| `21` | session created |
| `22` | session spent |
| `23` | session revoked |
| `24` | guardian rotated |
| `25` | recovery initiated |
| `26` | recovery executed |
| `27` | rental started |
| `28` | rental ended |
| `29` | ownership transferred |
| `30` | session updated |
| `31` | recovery canceled |

### Audit-lite caveats

::: danger Time is caller-supplied or hard-coded
The contract never calls `host.block_time`. `initiate_recovery` and `set_tenant` write against a
hard-coded reference timestamp `1_750_000_000`, while `finalize_recovery(now_timestamp)` and
`get_active_tenant(now_timestamp)` accept the clock **from the caller**. Anyone can pass a large
timestamp and finalize a recovery immediately, bypassing the 72-hour timelock. A production account
must read `host.block_time` and ignore caller-supplied time.
:::

::: danger Sessions are bearer tokens, not authenticated keys
`spend_with_session`, `update_session_budget` and `revoke_session` carry **no caller field** and do
not call `caller_is`. Anyone who knows a `session_id` can spend its budget, reduce it, or revoke it.
The source header calls this residual "bearer-style" behavior. Do not model sessions as delegated
keys until the entry points authenticate a session public key (and a signature or caller binding).
:::

- The file's first header says "DEMO-GRADE … DO NOT deploy with value without a full audit"; a
  second header line then claims "Fully Audited & Pentested". The status line is the accurate one:
  there is no external audit behind this contract. Do not repeat the "fully audited" claim.
- **`init` is permissionless.** The first caller chooses the owner; deploy and initialize atomically
  (or make `init` creator-gated) in production.
- The anti-spam fee (`2_000_000_000`) and per-session fee are stored constants; no code collects
  them.
- `revoke_session` refuses a non-existent session, which prevents pre-emptive tombstone DoS, but it
  is still callable by anyone for an existing id.
- Entry points are `extern "C-unwind"` so a native test harness can observe auth traps with
  `catch_unwind`. On wasm this behaves like `extern "C"`: a panic becomes `unreachable` and the
  call reverts.
- Session ids are capped at 1,000,000 and stride 16, so the storage footprint is bounded; a
  contract that creates all of them would still hit the 4,096-key chain cap long before that.

## Forking checklist

If you copy any of these contracts:

1. Replace integer ids with 32-byte addresses, or bound ids to a range that cannot collide.
2. Keep `caller_is` on **every** value-moving path; add it to session spend/revoke.
3. Replace caller-supplied time with `block_time`.
4. Add `min_out` + `deadline` to swaps, and an auction deadline + extension if you need
   snipe-resistance.
5. Add escrow before an auction or AMM moves real value.
6. Wire real token transfers or `send_message` calls before calling a pool "live".
7. Re-run the full test suite, then get an external audit. The status headers are not marketing
   copy.

## Next

Continue with [Verification and upgrade](/contracts/verification-and-upgrade) before deploying any fork, then [Deploying and calling contracts](/contracts/deploy-and-call) for the transaction mechanics.
