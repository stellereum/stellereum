#!/usr/bin/env python3
"""TPS load-measurement harness for the Stellereum 2-node test stand.

Measures REAL end-to-end throughput over JSON-RPC (not in-process apply):
  fund N accounts via ``stell_faucet`` (default) or via locally-signed
  transfers with ``--direct-fund-key`` -> blast M signed txs via
  ``stell_sendRawTransaction`` -> poll ``stell_blockNumber`` /
  ``stell_getTransactionReceipt`` until finalized -> print one-page summary.

All RPC calls use only the Python standard library (urllib). Transaction
signing needs ``cryptography`` (``pip install cryptography``); the
``--check-only`` and ``--plan`` modes work with stdlib alone and change
nothing on chain.

NONCE DISCIPLINE (the NonceGap fix): the node's mempool admits a nonce at
most NONCE_FUTURE_WINDOW=16 past the sender's executable head (see
``Mempool::NONCE_FUTURE_WINDOW`` in src/mempool.rs). Firing one sender's
nonces concurrently lets arrivals race, so any chain deeper than 16 past
the head dies with NonceGap rejects. This harness submits each account's
nonces SEQUENTIALLY (nonce k is sent only after k-1's submit returned)
while different accounts run IN PARALLEL. Arrival order per sender is
therefore nonce order, the head advances monotonically, and depth no
longer matters. Funding always precedes blasting (fund -> wait for
finality/balances -> blast), and every wave logs a rejection breakdown by
submit-error message.

Operable entirely through env vars (CLI flags override):

    STELL_RPC_URL       nodeA RPC endpoint (default http://127.0.0.1:8545/)
    STELL_RPC_URL_B     nodeB RPC endpoint (receipt fallback poll; receipts
                        are node-local so both nodes are queried)
    STELL_FAUCET_TOKEN  value of the node's STELL_FAUCET_TOKEN (required)
    STELL_RPC_AUTH_TOKEN value of the node's STELL_RPC_AUTH_TOKEN (if set)
    STELL_N             funded accounts (default 10)
    STELL_M             total transactions (default 1000)
    STELL_SSH_HOST      e.g. root@212.113.103.105, for FINALIZED log tail

REFERENCE (from src/rpc.rs -- keep in sync):
  stell_faucet params: {"address": hex32, "token": ..., "amount"?: u64}
    - token also accepted as "apiKey" or X-Api-Key / Authorization header
    - default drip 10 STELL (STELL_FAUCET_DRIP_STELL overrides), lifetime cap
      1000 STELL per address (src/main.rs)
    - the drip executes on the RECIPIENT's shard (bare hex32 routes to the
      workchain; "-1:<hex>" names a masterchain account). On a sharded node
      the faucet serves only its own shard and refuses other shards at
      admission, so fund masterchain accounts with "-1:<hex>" form.
  stell_sendRawTransaction params: {"tx": hex(bincode(Transaction)), "token"?: ...}
  stell_getBalance params: "hex32" (or {"address": hex32}) -> {balance, nonce}
  stell_getTransactionReceipt params: "hexhash" -> receipt | {status: pending|unknown}
  stell_blockNumber -> "0x<height>"
"""

import argparse
import collections
import concurrent.futures as cf
import json
import os
import struct
import sys
import time
import urllib.request
import urllib.error

# ---------------------------------------------------------------- crypto ---

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False

# bincode 1.3 layout of Transaction with EMPTY payload (see src/sharding.rs):
#   from[32] to[32] amount:u64LE gas:u64LE nonce:u64LE
#   source_shard:u32LE target_shard:u32LE
#   signature: u64LE len (=64) + 64 bytes
#   payload:   u64LE len (=0)
BINCODE_TX_LEN_EMPTY = 32 + 32 + 8 + 8 + 8 + 4 + 4 + 8 + 64 + 8  # = 176

# bincode 1.3 of an empty Vec<OpCode>: u64 LE length prefix only.
EMPTY_PAYLOAD_BINCODE = struct.pack("<Q", 0)


def signing_message(from_pub: bytes, to: bytes, amount: int, gas: int,
                    nonce: int, src_shard: int, dst_shard: int) -> bytes:
    """Exact bytes the sender signs (Transaction::signing_message, empty payload)."""
    msg = bytearray()
    msg += from_pub
    msg += to
    msg += struct.pack(">Q", amount)
    msg += struct.pack(">Q", gas)
    msg += struct.pack(">Q", nonce)
    msg += struct.pack(">I", src_shard)
    msg += struct.pack(">I", dst_shard)
    msg += b"PAYLOAD"
    msg += struct.pack(">I", len(EMPTY_PAYLOAD_BINCODE))
    msg += EMPTY_PAYLOAD_BINCODE
    return bytes(msg)


def bincode_encode_tx(from_pub: bytes, to: bytes, amount: int, gas: int,
                      nonce: int, src_shard: int, dst_shard: int,
                      signature: bytes) -> bytes:
    assert len(from_pub) == 32 and len(to) == 32 and len(signature) == 64
    out = bytearray()
    out += from_pub
    out += to
    out += struct.pack("<Q", amount)
    out += struct.pack("<Q", gas)
    out += struct.pack("<Q", nonce)
    out += struct.pack("<I", src_shard)
    out += struct.pack("<I", dst_shard)
    out += struct.pack("<Q", len(signature)) + signature
    out += struct.pack("<Q", 0)  # empty payload
    assert len(out) == BINCODE_TX_LEN_EMPTY, len(out)
    return bytes(out)


def gen_keypair():
    if not HAVE_CRYPTO:
        sys.exit("ERROR: 'cryptography' package required for signing "
                 "(pip install cryptography). --check-only/--plan work without it.")
    sk = Ed25519PrivateKey.generate()
    raw = sk.private_bytes_raw() if hasattr(sk, "private_bytes_raw") else None
    if raw is None:  # older versions: derive from DCE encoding
        from cryptography.hazmat.primitives import serialization
        raw = sk.private_bytes(serialization.Encoding.Raw,
                               serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())
    pub = sk.public_key().public_bytes_raw() if hasattr(sk.public_key(), "public_bytes_raw") else None
    if pub is None:
        from cryptography.hazmat.primitives import serialization
        pub = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)
    return sk, pub


def funder_keypair_from_hex(hex_str: str):
    """Derive (sk, pub_bytes) from a 32-byte hex seed for --direct-fund-key."""
    if not HAVE_CRYPTO:
        sys.exit("ERROR: 'cryptography' package required for --direct-fund-key signing "
                 "(pip install cryptography). --check-only/--plan work without it.")
    s = (hex_str or "").strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    try:
        seed = bytes.fromhex(s)
    except ValueError:
        sys.exit("ERROR: --direct-fund-key must be 64 hex chars (32-byte seed).")
    if len(seed) != 32:
        sys.exit("ERROR: --direct-fund-key must be 64 hex chars (32-byte seed).")
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes_raw() if hasattr(sk.public_key(), "public_bytes_raw") else None
    if pub is None:
        from cryptography.hazmat.primitives import serialization
        pub = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)
    return sk, bytes(pub)


def direct_fund_amount_per_account(per_acct: int, amount: int, gas: int) -> int:
    """Cover one account's blast spend ((amount+gas) per tx) plus one fee headroom."""
    return per_acct * (amount + gas) + gas


# ------------------------------------------------------- keys-file/resume ---


def _sk_to_seed_hex(sk) -> str:
    raw = sk.private_bytes_raw() if hasattr(sk, "private_bytes_raw") else None
    if raw is None:
        from cryptography.hazmat.primitives import serialization
        raw = sk.private_bytes(serialization.Encoding.Raw,
                               serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())
    return bytes(raw).hex()


def save_keys_file(path: str, keys, pubs) -> None:
    """Save generated keypairs as hex JSON: [{private, public}, ...]."""
    data = [{"private": _sk_to_seed_hex(sk), "public": pub.hex()}
            for sk, pub in zip(keys, pubs)]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load_keys_file(path: str):
    """Load keypairs saved by save_keys_file. Returns (sks, pubs_bytes)."""
    if not HAVE_CRYPTO:
        sys.exit("ERROR: 'cryptography' package required to load --keys-file "
                 "(pip install cryptography). --plan works without it.")
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, dict) and "keys" in data:
        data = data["keys"]
    if not isinstance(data, list) or not data:
        sys.exit(f"ERROR: --keys-file {path}: expected non-empty JSON list.")
    sks, pubs = [], []
    for i, e in enumerate(data):
        if isinstance(e, str):
            priv_hex, pub_hex = e, None
        elif isinstance(e, dict):
            priv_hex = e.get("private", e.get("priv", e.get("seed", e.get("secret", ""))))
            pub_hex = e.get("public", e.get("pub", e.get("address", None)))
        else:
            sys.exit(f"ERROR: --keys-file {path} entry {i}: bad shape.")
        s = (priv_hex or "").strip()
        if s.lower().startswith("0x"):
            s = s[2:]
        try:
            seed = bytes.fromhex(s)
        except ValueError:
            sys.exit(f"ERROR: --keys-file {path} entry {i}: bad private hex.")
        if len(seed) != 32:
            sys.exit(f"ERROR: --keys-file {path} entry {i}: private must be 32 bytes.")
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        pub = sk.public_key().public_bytes_raw() if hasattr(sk.public_key(), "public_bytes_raw") else None
        if pub is None:
            from cryptography.hazmat.primitives import serialization
            pub = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw)
        pub = bytes(pub)
        if pub_hex:
            ph = pub_hex.strip()
            if ph.lower().startswith("0x"):
                ph = ph[2:]
            if ph.lower() != pub.hex().lower():
                print(f"  WARNING: keys-file entry {i} public mismatch (derived {pub.hex()[:16]}... "
                      f"!= stored {ph[:16]}...); using derived.")
        sks.append(sk)
        pubs.append(pub)
    return sks, pubs


def count_keys_file(path: str):
    """Count accounts in a keys file without crypto (for --plan, no network)."""
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, dict) and "keys" in data:
        data = data["keys"]
    if not isinstance(data, list):
        return None
    return len(data)


def target_counts(n_accts: int, m_txs: int):
    """Per-account blast targets summing exactly to M (overshoot trimmed from end)."""
    per_acct = (m_txs + n_accts - 1) // n_accts
    targets = [per_acct] * n_accts
    over = n_accts * per_acct - m_txs
    for i in range(n_accts - 1, -1, -1):
        if over <= 0:
            break
        cut = min(targets[i], over)
        targets[i] -= cut
        over -= cut
    return per_acct, targets


def fetch_current_nonces(rpc, pubs):
    """Query CURRENT on-chain nonce per account via stell_getBalance (parallel)."""
    nonces, errors = {}, []

    def q(pub):
        return rpc.call("stell_getBalance", pub.hex())

    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(q, pub): pub for pub in pubs}
        for f in cf.as_completed(futs):
            pub = futs[f]
            try:
                res, err = f.result()
            except Exception as e:  # pragma: no cover
                res, err = None, str(e)
            h = pub.hex()
            if err or not isinstance(res, dict):
                errors.append((h[:16], err or res))
            else:
                try:
                    nonces[h] = int(res.get("nonce", 0))
                except (TypeError, ValueError):
                    errors.append((h[:16], f"bad nonce in {res}"))
    return nonces, errors

# ------------------------------------------------------------------ rpc ---


class Rpc:
    def __init__(self, url: str, api_token: str = "", timeout: float = 15.0):
        self.url = url.rstrip("/") + "/"
        self.api_token = api_token
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params=None):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id,
                           "method": method, "params": params if params is not None else {}}).encode()
        req = urllib.request.Request(self.url, data=body,
                                     headers={"Content-Type": "application/json"})
        if self.api_token:
            req.add_header("X-Api-Key", self.api_token)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                resp = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return None, f"http-{e.code}"
        except Exception as e:  # connection refused etc.
            return None, f"net-error: {e}"
        if resp.get("error"):
            return None, str(resp["error"].get("message", resp["error"]))
        return resp.get("result"), None


def parse_blocknumber(v) -> int:
    if isinstance(v, str):
        return int(v, 16)
    return int(v)


def build_rpcs(a):
    """Primary RPC plus the --rpc-url-b fallback (receipts are node-local)."""
    rpcs = [Rpc(a.rpc_url, a.api_token)]
    url_b = (getattr(a, "rpc_url_b", "") or "").strip()
    if url_b and url_b != a.rpc_url:
        rpcs.append(Rpc(url_b, a.api_token))
    return rpcs

# ----------------------------------------------------------------- modes ---


def do_check_only(rpc: Rpc) -> bool:
    """Prove each RPC method the harness needs EXISTS, without changing state.

    Starts with the OFFLINE checks (no network): wave math, per-account
    chain contiguity, rejection tallying. If no live chain answers, the RPC
    probes are SKIPPED and the exit code reflects the offline checks alone,
    so this mode validates the harness without a node up.
    """
    print("offline harness checks (no RPC, no signing)\n")
    ok_off = run_offline_checks(verbose=True)
    print()

    chain, cerr = rpc.call("stell_chainId", {})
    if cerr and ("net-error" in cerr or cerr.startswith("http-")):
        print(f"no live chain at {rpc.url} ({cerr}): RPC probes SKIPPED.")
        print("run with a node up for the full method-existence probe.\n")
        print("check-only: " + ("OFFLINE CHECKS PASS (no chain probed)"
                                if ok_off else "OFFLINE CHECKS FAILED"))
        return ok_off

    print(f"RPC method-existence probe against {rpc.url}\n")
    ok_all = True

    def probe(name, method, params, expect):
        nonlocal ok_all
        res, err = rpc.call(method, params)
        if err and "method not found" in err:
            print(f"  [MISSING] {name:28s} {method}: method not found")
            ok_all = False
        elif err and "net-error" in err or err and err.startswith("http-"):
            print(f"  [UNREACHABLE] {name:28s} {method}: {err}")
            ok_all = False
        else:
            print(f"  [EXISTS]  {name:28s} {method}: {expect} "
                  f"(result={json.dumps(res)[:60]}, err={err})")

    probe("chain id", "stell_chainId", {}, "node answers")
    probe("block number", "stell_blockNumber", {}, "expect 0x<height>")
    probe("mempool size", "stell_mempoolSize", {}, "expect int")
    probe("balance/nonce", "stell_getBalance", "00" * 32, "expect {balance,nonce}")
    probe("latest blocks", "stell_latestBlocks", {}, "expect [...]")
    # Faucet probe uses a WRONG token: any auth/cap error proves the method
    # exists; only "method not found"/"disabled" is informative failure.
    probe("faucet (bad token)", "stell_faucet",
          {"address": "00" * 32, "token": "__tps_probe__"},
          "expect unauthorized/disabled error, NOT 'method not found'")
    # sendRawTransaction probe omits "tx": "missing tx" proves the method exists.
    probe("submit (no tx)", "stell_sendRawTransaction", {},
          "expect 'missing tx' error, NOT 'method not found'")
    probe("receipt", "stell_getTransactionReceipt", "00" * 32,
          "expect pending/unknown")
    probe("tx status", "stell_getTransactionStatus", "00" * 32,
          "expect unknown")
    print()
    print("check-only: " + ("ALL METHODS PRESENT" if ok_all and ok_off
                             else "PROBLEMS FOUND (see above)"))
    return ok_all and ok_off


def do_self_test() -> bool:
    """Offline round-trip: signing message, ed25519 sign/verify, bincode layout,
    plus the harness-math checks (wave plan, nonce chains, tally)."""
    print("self-test (offline, no RPC)\n")
    if not HAVE_CRYPTO:
        print("  SKIP: 'cryptography' not installed")
        return False
    sk, pub = gen_keypair()
    to = bytes(range(32))
    msg = signing_message(pub, to, 1, 1, 7, 0, 0)
    sig = sk.sign(msg)
    assert len(sig) == 64
    sk.public_key().verify(sig, msg)  # raises on failure
    # tamper must fail (flip a nonzero byte: byte 0 is pubkey, never 0x00-fixed)
    bad = bytearray(msg)
    bad[0] ^= 0xFF
    try:
        sk.public_key().verify(sig, bytes(bad))
        print("  FAIL: tampered message verified")
        return False
    except Exception:
        pass
    raw = bincode_encode_tx(pub, to, 1, 1, 7, 0, 0, sig)
    assert len(raw) == BINCODE_TX_LEN_EMPTY, len(raw)
    assert raw[:32] == pub and raw[32:64] == to
    assert struct.unpack("<Q", raw[64:72])[0] == 1      # amount LE
    assert struct.unpack("<Q", raw[72:80])[0] == 1      # gas LE
    assert struct.unpack("<Q", raw[80:88])[0] == 7      # nonce LE
    assert struct.unpack("<I", raw[88:92])[0] == 0      # src shard LE
    assert struct.unpack("<Q", raw[96:104])[0] == 64    # sig len LE
    assert raw[104:168] == sig
    assert struct.unpack("<Q", raw[168:176])[0] == 0    # empty payload
    print(f"  signing_message len : {len(msg)} bytes (expect 115)")
    assert len(msg) == 32 + 32 + 8 + 8 + 8 + 4 + 4 + 7 + 4 + 8 == 115
    print(f"  bincode tx len      : {len(raw)} bytes (expect 176)")
    print("  sign/verify         : OK, tamper rejected: OK")
    print("\nharness math checks (no RPC):")
    if not run_offline_checks(verbose=True):
        print("\nself-test: FAIL (harness math)")
        return False
    print("\nself-test: PASS")
    return True


def do_plan(a) -> None:
    resume = bool(getattr(a, "resume", False))
    keys_file = getattr(a, "keys_file", "") or ""
    n_plan = a.accounts
    if resume and keys_file:
        try:
            n_file = count_keys_file(keys_file)
        except Exception as e:
            n_file = None
            print(f"  WARNING keys-file: cannot read {keys_file}: {e}")
        if isinstance(n_file, int) and n_file > 0:
            if n_file != a.accounts:
                print(f"  NOTE keys-file  : {keys_file} holds {n_file} keys "
                      f"(overrides --accounts {a.accounts} for resume math)")
            n_plan = n_file
        elif n_file is not None:
            print(f"  WARNING keys-file: {keys_file} holds no keys; using --accounts {a.accounts}")
    per_acct, waves, wave_cap = plan_waves(n_plan, a.txs)
    _, targets = target_counts(n_plan, a.txs)
    print("plan (dry-run, no RPC, no signing)\n")
    print(f"  rpc url        : {a.rpc_url}")
    print(f"  accounts (N)   : {n_plan}")
    print(f"  txs (M)        : {a.txs}")
    print(f"  per account    : {per_acct} txs "
          f"({'exact' if n_plan * per_acct == a.txs else 'last account takes remainder'})")
    print(f"  mempool quota  : 256 tx/sender -> wave cap {wave_cap}/acct/wave")
    print(f"  waves          : {waves} (submit -> await finalize -> next)")
    print(f"  nonce order    : sequential per account, parallel across accounts "
          f"(no NonceGap: arrival order is nonce order)")
    if resume:
        print(f"  resume mode    : ON (re-blast only the REMAINDER per account)")
        print(f"  keys file      : {keys_file or '(none: pass --keys-file at --run to reload SAME keys)'}")
        print(f"  per-account target: {per_acct} txs/acct "
              f"({'exact' if sum(targets) == a.txs else f'tail-trimmed, sum={sum(targets)}'}) "
              f"(assumes fresh start nonce 0)")
        print(f"  remainder math : remaining[i] = target[i] - current_nonce[i], "
              f"current via stell_getBalance at --run (clipped at 0)")
        print(f"  waves (full)   : {waves}; resume waves = ceil(max(remaining)/{wave_cap}) <= full")
        print(f"  nonce contiguity: resume submits nonces "
              f"[current[i], target[i]) per account, {wave_cap}/acct/wave cap preserved")
        print(f"  per-account resumed-from/total printed at --run")
        print(f"  example        : 535/1000 finalized over N={n_plan} -> "
              f"remaining {a.txs - 535} spread per-account, "
              f"e.g. N=10: target 100/acct, ~53-54 done/acct -> ~46-47 remaining/acct, 1 wave")
    n_fund = n_plan if resume else a.accounts
    if getattr(a, "direct_fund_key", ""):
        fund_amount = direct_fund_amount_per_account(per_acct, a.amount, a.gas)
        print(f"  funding        : direct ({n_fund} local-signed transfers, "
              f"{fund_amount} each, gas={a.gas} shard={a.shard}->{a.shard})")
        print("  funding via direct path: --direct-fund-key present, "
              "on-chain nonce fetched via stell_getBalance at run time, "
              "contiguous nonces assigned locally (no faucet)")
    else:
        print(f"  faucet drips   : {n_fund} (drip=10 STELL default, cap=1000 STELL/addr)")
    print(f"  tx shape       : amount={a.amount} gas={a.gas} shard={a.shard}->{a.shard}")
    print(f"  submit workers : {a.workers}, poll every {a.poll_interval}s, "
          f"finalize timeout {a.timeout}s/wave")
    if a.ssh_host:
        print(f"  ssh tail       : {a.ssh_host} ({a.ssh_cmd})")
    print("\nNothing was sent. Add --run to execute, --check-only to probe RPC.")


def plan_waves(n_accts: int, m_txs: int, wave_cap: int = 200):
    per_acct = (m_txs + n_accts - 1) // n_accts
    waves = (per_acct + wave_cap - 1) // wave_cap
    return per_acct, waves, wave_cap


def wave_starts(nonces: dict, pubs, wave_idx: int, wave_cap: int) -> dict:
    """Effective per-account start nonce for one wave (pure, no network).

    ``nonces`` maps pubhex -> nonce observed after funding finality; each
    wave advances every account by ``wave_idx * wave_cap``.
    """
    return {pub.hex(): nonces[pub.hex()] + wave_idx * wave_cap for pub in pubs}


def build_wave_chains(starts: dict, counts, pubs):
    """Per-account nonce chains for one wave (pure, no network).

    Returns [(sender_idx, base, [nonces...], to_pub)]: every chain is
    contiguous ``[base, base+count)`` BY CONSTRUCTION — the property the
    sequential submitter relies on. Empty-count accounts are skipped.
    """
    chains = []
    for i, pub in enumerate(pubs):
        n = counts[i]
        if n <= 0:
            continue
        base = starts[pub.hex()]
        chains.append((i, base, list(range(base, base + n)), pubs[(i + 1) % len(pubs)]))
    return chains


def tally_rejections(errs) -> dict:
    """Break rejections down by submit-error message (pure, no network)."""
    tally = collections.Counter(e or "unknown" for e in errs)
    return dict(sorted(tally.items(), key=lambda kv: (-kv[1], kv[0])))


def fmt_tally(tally: dict) -> str:
    if not tally:
        return "none"
    return "; ".join(f"{c}x {m}" for m, c in tally.items())


def run_offline_checks(verbose: bool = True) -> bool:
    """Validate harness math with NO network and NO crypto (stdlib only).

    Covers the NonceGap fix directly: wave plan shape, per-account chain
    contiguity (the sequential-submit invariant), and rejection tallying.
    Returns True iff every check passes.
    """
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        if cond:
            if verbose:
                print(f"  [ok] {name} {detail}")
        else:
            ok = False
            print(f"  [FAIL] {name} {detail}")

    per_acct, waves, cap = plan_waves(10, 1000)
    check("wave math N=10 M=1000", (per_acct, waves, cap) == (100, 1, 200),
          f"(per_acct={per_acct} waves={waves} cap={cap})")
    per1, waves1, _ = plan_waves(10, 2500)
    check("wave math N=10 M=2500", (per1, waves1) == (250, 2),
          f"(per_acct={per1} waves={waves1})")
    _, targets = target_counts(10, 1000)
    check("targets sum to M", sum(targets) == 1000 and all(t == 100 for t in targets),
          f"(sum={sum(targets)})")
    _, targets2 = target_counts(3, 1000)
    check("targets trim overshoot", sum(targets2) == 1000, f"(sum={sum(targets2)})")

    # Chain contiguity on fake identities (hex strings stand in for pubs).
    class FakePub:
        def __init__(self, h): self._h = h
        def hex(self): return self._h
    pubs = [FakePub(f"{i:064x}") for i in range(3)]
    starts = {p.hex(): 7 + i for i, p in enumerate(pubs)}
    chains = build_wave_chains(starts, [5, 0, 20], pubs)
    check("empty accounts skipped", len(chains) == 2, f"({len(chains)} chains)")
    contiguous = all(ns == list(range(base, base + len(ns)))
                     for _, base, ns, _ in chains)
    check("chains contiguous", contiguous, "(nonce k follows k-1 per account)")
    gap_free = all(ns[0] == starts[pubs[i].hex()] for i, _, ns, _ in chains)
    check("chains start at observed head", gap_free, "(no nonce jump at wave start)")
    deep = build_wave_chains({pubs[0].hex(): 0}, [200], pubs[:1])
    check("200-deep chain stays one ordered chain", len(deep) == 1 and len(deep[0][2]) == 200,
          "(depth never fans out concurrently)")

    tally = tally_rejections(["NonceGap: expected 3 got 7", "NonceGap: expected 3 got 7",
                              "offered fee is below the base fee", None])
    check("tally groups by message",
          tally == {"NonceGap: expected 3 got 7": 2,
                    "offered fee is below the base fee": 1, "unknown": 1},
          f"({fmt_tally(tally)})")
    check("empty tally", tally_rejections([]) == {})
    return ok

# -------------------------------------------------------------- load run ---


def fund_accounts(rpc: Rpc, pubs, faucet_token: str):
    """One faucet drip per account, SEQUENTIAL (server nonces are serial)."""
    print(f"funding {len(pubs)} accounts via stell_faucet ...")
    t0 = time.time()
    credited, failed = 0, []
    for i, pub in enumerate(pubs):
        res, err = rpc.call("stell_faucet", {"address": pub.hex(), "token": faucet_token})
        if err:
            failed.append((pub.hex()[:16], err))
        else:
            credited += 1
        if (i + 1) % 10 == 0 or i + 1 == len(pubs):
            print(f"  faucet {i + 1}/{len(pubs)} ...", flush=True)
    dt = time.time() - t0
    print(f"  funded {credited}/{len(pubs)} in {dt:.1f}s")
    for addr, err in failed[:10]:
        print(f"  faucet FAILED {addr}...: {err}")
    return credited


def direct_fund_accounts(rpc: Rpc, pubs, fund_key_hex: str,
                         fund_amount: int, fund_gas: int, shard: int):
    """Fund accounts by signing transfers LOCALLY with the given 32-byte seed.

    Fetches the CURRENT on-chain nonce of the derived funder account via
    stell_getBalance, then assigns contiguous nonces (base, base+1, ...).
    Submits each signed transfer via stell_sendRawTransaction, SEQUENTIAL
    (nonces are serial). Returns the number credited.
    """
    sk, funder_pub = funder_keypair_from_hex(fund_key_hex)
    res, err = rpc.call("stell_getBalance", funder_pub.hex())
    if err or not isinstance(res, dict):
        print(f"  direct funding FAILED: stell_getBalance {funder_pub.hex()[:16]}...: {err or res}")
        return 0
    try:
        base_nonce = int(res.get("nonce", 0))
    except (TypeError, ValueError):
        print(f"  direct funding FAILED: bad nonce in {res}")
        return 0
    print(f"direct-funding {len(pubs)} accounts from {funder_pub.hex()[:16]}... "
          f"(base nonce {base_nonce}, {fund_amount} each, contiguous nonces) ...")
    t0 = time.time()
    credited, failed = 0, []
    for i, pub in enumerate(pubs):
        nonce = base_nonce + i
        msg = signing_message(funder_pub, pub, fund_amount, fund_gas, nonce, shard, shard)
        raw = bincode_encode_tx(funder_pub, pub, fund_amount, fund_gas,
                                nonce, shard, shard, sk.sign(msg))
        params = {"tx": raw.hex()}
        if rpc.api_token:
            params["token"] = rpc.api_token
        _, serr = rpc.call("stell_sendRawTransaction", params)
        if serr:
            failed.append((pub.hex()[:16], serr))
        else:
            credited += 1
        if (i + 1) % 10 == 0 or i + 1 == len(pubs):
            print(f"  direct-fund {i + 1}/{len(pubs)} ...", flush=True)
    dt = time.time() - t0
    print(f"  direct-funded {credited}/{len(pubs)} in {dt:.1f}s")
    for addr, serr in failed[:10]:
        print(f"  direct-fund FAILED {addr}...: {serr}")
    return credited


def wait_balances(rpc: Rpc, pubs, timeout: float, poll: float = 1.0):
    """Wait until every funded account shows a nonzero balance + fetch nonces."""
    print("waiting for funding to finalize ...")
    t0 = time.time()
    nonces = {}
    pending = set(p.hex() for p in pubs)
    while pending and time.time() - t0 < timeout:
        def q(h):
            return rpc.call("stell_getBalance", h)
        with cf.ThreadPoolExecutor(max_workers=16) as ex:
            futs = {ex.submit(q, h): h for h in list(pending)}
            for f in cf.as_completed(futs):
                h = futs[f]
                try:
                    res, err = f.result()
                except Exception as e:  # pragma: no cover
                    res, err = None, str(e)
                if not err and res and int(res.get("balance", "0")) > 0:
                    nonces[h] = int(res.get("nonce", 0))
                    pending.discard(h)
        if pending:
            time.sleep(poll)
    dt = time.time() - t0
    print(f"  visible {len(nonces)}/{len(pubs)} after {dt:.1f}s")
    return nonces, dt


def blast_wave(rpc: Rpc, keys, pubs, nonces, wave_idx: int, txs_this_wave,
               amount: int, gas: int, shard: int, workers: int):
    """Sign + submit one wave with the NonceGap-safe discipline.

    Each account's nonces go out SEQUENTIALLY (k only after k-1's submit
    returned), so per-sender arrival order IS nonce order and the mempool
    head advances monotonically — depth no longer matters. Different
    accounts submit IN PARALLEL (one worker per account). Returns
    (accepted_hashes, rejected_count, submit_secs, reject_tally) where
    reject_tally breaks rejections down by submit-error message.
    """
    counts = txs_this_wave["counts"]
    cap = txs_this_wave["per_acct_cap"]
    starts = wave_starts(nonces, pubs, wave_idx, cap)
    chains = build_wave_chains(starts, counts, pubs)
    t0 = time.time()

    def run_account(chain):
        i, base, ns, to = chain
        sk, pub = keys[i], pubs[i]
        acc, errs = [], []
        for nonce in ns:
            msg = signing_message(pub, to, amount, gas, nonce, shard, shard)
            raw = bincode_encode_tx(pub, to, amount, gas, nonce, shard, shard, sk.sign(msg))
            params = {"tx": raw.hex()}
            if rpc.api_token:
                params["token"] = rpc.api_token
            res, err = rpc.call("stell_sendRawTransaction", params)
            if res:
                acc.append(res)
            else:
                errs.append(err or "unknown")
        return acc, errs

    accepted, all_errs = [], []
    if chains:
        with cf.ThreadPoolExecutor(max_workers=min(workers, len(chains))) as ex:
            futs = [ex.submit(run_account, c) for c in chains]
            for j, f in enumerate(futs):
                acc, errs = f.result()
                accepted.extend(acc)
                all_errs.extend(errs)
                if (j + 1) % 10 == 0 or j + 1 == len(futs):
                    print(f"  submitted accounts {j + 1}/{len(futs)} "
                          f"({len(accepted)} accepted, {len(all_errs)} rejected) ...", flush=True)
    dt = time.time() - t0
    tally = tally_rejections(all_errs)
    if tally:
        print(f"  rejection breakdown: {fmt_tally(tally)}")
    return accepted, len(all_errs), dt, tally


def await_finalized(rpcs, hashes, timeout: float, poll: float):
    """Poll receipts until all hashes resolve to success/failed. Returns stats.

    `rpcs` is a list of Rpc clients (primary first). Receipts are node-local:
    a node that finalizes a height without the block body records the block
    with txs=0 and files NO receipts (observed live: nodeB held success
    receipts for txs nodeA reported "unknown", while nodeA state had clearly
    advanced). Every still-pending hash is therefore re-queried on each
    fallback node before giving up for the round. `via_fallback` counts txs
    first seen on a non-primary node. `heights` maps receipt height ->
    finalized tx count, so the summary can report true per-height packing
    even though each node's stell_latestBlocks shows txs=0 for heights
    adopted from its peer (bodies/receipts are proposer-local).
    """
    if isinstance(rpcs, Rpc):
        rpcs = [rpcs]
    t0 = time.time()
    pending = set(hashes)
    success = failed = via_fallback = 0
    heights = {}
    t_first = None

    def poll_one(args):
        rpc, h = args
        return h, rpc.call("stell_getTransactionReceipt", h)

    while pending and time.time() - t0 < timeout:
        for ri, rpc in enumerate(rpcs):
            if not pending:
                break
            with cf.ThreadPoolExecutor(max_workers=16) as ex:
                futs = [ex.submit(poll_one, (rpc, h)) for h in list(pending)]
                for f in cf.as_completed(futs):
                    h, (res, err) = f.result()
                    if err or res is None:
                        continue
                    st = res.get("status", "")
                    if st in ("success", "failed"):
                        pending.discard(h)
                        if st == "success":
                            success += 1
                        else:
                            failed += 1
                        try:
                            hh = res.get("height", None)
                            hh = int(hh) if hh is not None else None
                        except (TypeError, ValueError):
                            hh = None
                        if hh is not None:
                            heights[hh] = heights.get(hh, 0) + 1
                        if ri > 0:
                            via_fallback += 1
                        if t_first is None:
                            t_first = time.time() - t0
            # fall through to the next node for whatever is still pending
        if pending:
            time.sleep(poll)
    dt = time.time() - t0
    return {"success": success, "failed": failed, "pending": len(pending),
            "t_first": t_first, "t_all": dt if not pending else None,
            "via_fallback": via_fallback, "heights": heights}


def merged_latest(rpcs, n: int = 12):
    """Merge stell_latestBlocks across nodes by height (max txs wins).

    Each node reports txs=0 for heights it adopted without the body, so a
    single node's view hides real packing. Merging both views recovers the
    proposer's tx counts per height.
    """
    if isinstance(rpcs, Rpc):
        rpcs = [rpcs]
    merged = {}
    for rpc in rpcs:
        res, _ = rpc.call("stell_latestBlocks", {})
        if not isinstance(res, list):
            continue
        for b in res:
            if not isinstance(b, dict):
                continue
            try:
                h = int(b.get("height"))
            except (TypeError, ValueError):
                continue
            try:
                t = int(b.get("txs", 0))
            except (TypeError, ValueError):
                t = 0
            if h not in merged or t > merged[h].get("txs", 0):
                merged[h] = {"height": h, "txs": t}
    return sorted(merged.values(), key=lambda b: b["height"], reverse=True)[:n]


def fmt_packing(heights) -> str:
    """One-line per-height packing summary from a {height: count} map."""
    if not heights:
        return "n/a (no receipt heights)"
    hs = sorted(heights)
    counts = [heights[h] for h in hs]
    return (f"{len(hs)} heights [{hs[0]}..{hs[-1]}], max {max(counts)}, "
            f"avg {sum(counts) / len(counts):.0f}, " +
            ", ".join(f"h={h}:{heights[h]}" for h in hs[:12]) +
            (" ..." if len(hs) > 12 else ""))


def run_blast(rpc: Rpc, a, chain, h0i, h0, keys, pubs, base_nonces,
              remainings, total_to_send: int, wave_cap: int,
              funding_label: str, fund_wait: float, use_direct: bool) -> int:
    """Blast only the per-account REMAINDER (resume path).

    base_nonces: {pubhex: current on-chain nonce} (contiguous start per account).
    remainings:  per-account tx counts left to reach the original target.
    Preserves contiguous nonces [start, start+remaining) and the wave cap.
    """
    import math
    max_rem = max(remainings) if remainings else 0
    waves = int(math.ceil(max_rem / wave_cap)) if max_rem > 0 else 0
    print(f"blast (resume): {total_to_send} txs over {len(pubs)} accounts in {waves} wave(s)")
    t_blast0 = time.time()
    total_accepted = total_rejected = 0
    all_tally = collections.Counter()
    submit_secs = 0.0
    finalize_stats = []
    for w in range(waves):
        counts = []
        for rem in remainings:
            already = w * wave_cap
            counts.append(max(0, min(wave_cap, rem - already)))
        over = sum(counts) - (total_to_send - total_accepted - total_rejected)
        if over > 0:
            for i in range(len(counts) - 1, -1, -1):
                cut = min(counts[i], over)
                counts[i] -= cut
                over -= cut
                if over <= 0:
                    break
        if sum(counts) == 0:
            break
        accepted, rejected, dt, tally = blast_wave(
            rpc, keys, pubs, base_nonces, w,
            {"counts": counts, "per_acct_cap": wave_cap},
            a.amount, a.gas, a.shard, a.workers)
        total_accepted += len(accepted)
        total_rejected += rejected
        all_tally.update(tally)
        submit_secs += dt
        print(f"  wave {w + 1}/{waves}: accepted {len(accepted)} rejected {rejected} "
              f"in {dt:.2f}s ({len(accepted) / dt:.0f} tx/s submit)" if dt > 0 else
              f"  wave {w + 1}/{waves}: accepted {len(accepted)} rejected {rejected}")
        if tally:
            print(f"  wave {w + 1} rejections: {fmt_tally(tally)}")
        st = await_finalized(build_rpcs(a), accepted, a.timeout, a.poll_interval)
        finalize_stats.append(st)
        print(f"  wave {w + 1} finalize: success={st['success']} failed={st['failed']} "
              f"pending={st['pending']} t_first={st['t_first']} t_all={st['t_all']} "
              f"via_fallback={st.get('via_fallback', 0)}")
    blast_wall = time.time() - t_blast0
    h1, _ = rpc.call("stell_blockNumber", {})
    h1i = parse_blocknumber(h1) if h1 is not None else -1
    s_ok = sum(s["success"] for s in finalize_stats)
    s_fail = sum(s["failed"] for s in finalize_stats)
    s_pend = sum(s["pending"] for s in finalize_stats)
    s_fb = sum(s.get("via_fallback", 0) for s in finalize_stats)
    t_first_all = next((s["t_first"] for s in finalize_stats if s["t_first"] is not None), None)
    e2e_tps = s_ok / blast_wall if blast_wall > 0 else 0.0
    sub_rate = total_accepted / submit_secs if submit_secs > 0 else 0.0
    all_heights = {}
    for s in finalize_stats:
        for h, c in (s.get("heights") or {}).items():
            all_heights[h] = all_heights.get(h, 0) + c
    latest = merged_latest(build_rpcs(a))
    print()
    print("=" * 64)
    print("TPS LOAD SUMMARY (resume)")
    print("=" * 64)
    print(f"rpc               : {a.rpc_url} (chain {chain})")
    print(f"accounts / txs    : N={len(pubs)} M={a.txs} (amount={a.amount} gas={a.gas} shard={a.shard})")
    print(f"funding           : {funding_label} (no refuel; remainder only, wait {fund_wait:.1f}s)")
    print(f"submission rate   : {sub_rate:.0f} tx/s ({total_accepted} accepted, "
          f"{total_rejected} rejected in {submit_secs:.2f}s)")
    print(f"rejections        : {fmt_tally(dict(all_tally))}")
    print(f"blocks            : {h0i} -> {h1i} ({(h1i - h0i) if h0i >= 0 and h1i >= 0 else '?'} heights)")
    print(f"time-to-finalize  : first {t_first_all}s" if t_first_all is not None else "time-to-finalize  : n/a")
    print(f"end-to-end TPS    : {e2e_tps:.0f} tx/s ({s_ok} success / {s_fail} failed / "
          f"{s_pend} pending over {blast_wall:.1f}s wall, {s_fb} via fallback RPC)")
    print(f"block packing     : {fmt_packing(all_heights)} (from receipts, both nodes)")
    if latest:
        print("recent blocks     : " + ", ".join(
            f"h={b.get('height')} txs={b.get('txs')}" for b in latest[:8]) +
            " (merged A+B, max txs wins)")
    print("nonce discipline  : sequential per account, parallel across accounts "
          "(no NonceGap: arrival order is nonce order)")
    print("bottleneck read   : execution is NOT it (in-process micro-bench, dev release:")
    print("                    Token ~613k tx/s, Native ~26k tx/s).")
    print("                    cap = consensus: 3s round timeout + STELL_MIN_BLOCK_MS")
    print("                    floor (400ms) + MAX_BLOCK_TXS 10k + mempool 10k/256-per-sender.")
    print("=" * 64)
    if a.ssh_host:
        ssh_tail(a.ssh_host, a.ssh_cmd)
    return 0 if s_pend == 0 and total_rejected == 0 else 2


def ssh_tail(host: str, cmd: str):
    import subprocess
    try:
        p = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                            host, cmd], capture_output=True, text=True, timeout=20)
        out = (p.stdout or "")[-2000:]
        print(f"--- ssh {host} tail (rc={p.returncode}) ---")
        print(out or "(empty)")
        if p.stderr:
            print("(stderr) " + p.stderr[-500:])
    except Exception as e:
        print(f"--- ssh tail skipped: {e} ---")


def run_load(a) -> int:
    use_direct = bool(getattr(a, "direct_fund_key", ""))
    resume = bool(getattr(a, "resume", False))
    keys_file = getattr(a, "keys_file", "") or ""
    if resume:
        if not keys_file:
            sys.exit("ERROR: --resume requires --keys-file <path> with the SAME keys "
                     "as the original run (keypairs are saved automatically when --keys-file "
                     "is passed without --resume).")
        if not os.path.exists(keys_file):
            sys.exit(f"ERROR: --keys-file {keys_file} not found; cannot resume without SAME keys.")
        if use_direct:
            print("NOTE: --resume ignores funding flags (--direct-fund-key/--faucet-token); "
                  "accounts are already funded, only the remainder is re-blasted.")
    if not resume and not use_direct and not a.faucet_token:
        sys.exit("ERROR: faucet token required (--faucet-token or STELL_FAUCET_TOKEN). "
                 "The live stand keeps it in /root/env.A as STELL_FAUCET_TOKEN. "
                 "Alternatively pass --direct-fund-key to bypass the faucet.")
    rpc = Rpc(a.rpc_url, a.api_token)
    chain, err = rpc.call("stell_chainId", {})
    if err:
        sys.exit(f"ERROR: cannot reach RPC {a.rpc_url}: {err}")
    h0, err = rpc.call("stell_blockNumber", {})
    h0i = parse_blocknumber(h0) if not err else -1
    print(f"chainId={chain} start_height={h0} mempool: {rpc.call('stell_mempoolSize', {})[0]}")

    if resume:
        keys, pubs = load_keys_file(keys_file)
        if len(pubs) != a.accounts:
            print(f"NOTE: keys-file holds {len(pubs)} accounts, "
                  f"overriding --accounts {a.accounts} (SAME keys win).")
        per_acct, targets = target_counts(len(pubs), a.txs)
        _, _, wave_cap = plan_waves(len(pubs), a.txs)
        print(f"resume: querying CURRENT nonces for {len(pubs)} accounts via stell_getBalance ...")
        cur_nonces, errors = fetch_current_nonces(rpc, pubs)
        if errors or len(cur_nonces) < len(pubs):
            for addr, e in errors[:10]:
                print(f"  stell_getBalance FAILED {addr}...: {e}")
            missing = len(pubs) - len(cur_nonces)
            sys.exit(f"ERROR: resume needs CURRENT nonce for every account "
                     f"({missing} missing); aborting to preserve contiguous nonces.")
        remainings = []
        total_done = 0
        for i, pub in enumerate(pubs):
            cur = cur_nonces[pub.hex()]
            tgt = targets[i]
            done = min(cur, tgt)  # assumes fresh start nonce 0
            rem = max(0, tgt - cur)
            remainings.append(rem)
            total_done += done
            print(f"  acct {i} {pub.hex()[:16]}...: resumed-from {cur}/total {tgt} "
                  f"(remaining {rem})")
        total_remaining = sum(remainings)
        print(f"resume: {total_done}/{a.txs} already finalized on chain, "
              f"re-blasting remainder {total_remaining}/{a.txs} "
              f"({len(pubs)} accounts, target {per_acct}/acct, cap {wave_cap}/acct/wave)")
        if total_remaining == 0:
            print("resume: nothing to do (all accounts at/above target).")
            return 0
        return run_blast(rpc, a, chain, h0i, h0, keys, pubs, cur_nonces,
                         remainings, total_remaining, wave_cap,
                         funding_label=f"resume via {keys_file}",
                         fund_wait=0.0, use_direct=True)

    print(f"generating {a.accounts} ed25519 accounts ...")
    keys, pubs = [], []
    for _ in range(a.accounts):
        sk, pub = gen_keypair()
        keys.append(sk)
        pubs.append(pub)
    if keys_file:
        save_keys_file(keys_file, keys, pubs)
        print(f"  keys saved to {keys_file} ({len(pubs)} keypairs, hex JSON); "
              f"reuse with --keys-file + --resume to re-blast only the remainder.")

    if use_direct:
        per_acct0, _, _ = plan_waves(len(pubs), a.txs)
        fund_amount = direct_fund_amount_per_account(per_acct0, a.amount, a.gas)
        direct_fund_accounts(rpc, pubs, a.direct_fund_key, fund_amount, a.gas, a.shard)
    else:
        fund_accounts(rpc, pubs, a.faucet_token)
    nonces, fund_wait = wait_balances(rpc, pubs, timeout=a.timeout, poll=a.poll_interval)
    if len(nonces) < len(pubs):
        print(f"WARNING: only {len(nonces)}/{len(pubs)} funded; continuing with those")
        idx = [i for i, p in enumerate(pubs) if p.hex() in nonces]
        keys = [keys[i] for i in idx]
        pubs = [pubs[i] for i in idx]
        if not pubs:
            sys.exit("ERROR: no funded accounts, aborting blast.")

    per_acct, waves, wave_cap = plan_waves(len(pubs), a.txs)
    print(f"blast: {a.txs} txs over {len(pubs)} accounts in {waves} wave(s) "
          f"(sequential per account, parallel across accounts)")
    all_hashes = []
    t_blast0 = time.time()
    h_first = h0i
    total_accepted = total_rejected = 0
    all_tally = collections.Counter()
    submit_secs = 0.0
    finalize_stats = []
    for w in range(waves):
        # per-account count for this wave
        counts = []
        for i in range(len(pubs)):
            already = w * wave_cap
            want = min(wave_cap, per_acct - already)
            # last wave trims the global remainder
            counts.append(max(0, want))
        # trim overshoot on final wave
        over = sum(counts) - (a.txs - total_accepted - total_rejected)
        if over > 0:
            for i in range(len(counts) - 1, -1, -1):
                cut = min(counts[i], over)
                counts[i] -= cut
                over -= cut
                if over <= 0:
                    break
        if sum(counts) == 0:
            break
        t_h, _ = rpc.call("stell_blockNumber", {})
        accepted, rejected, dt, tally = blast_wave(
            rpc, keys, pubs, nonces, w,
            {"counts": counts, "per_acct_cap": wave_cap},
            a.amount, a.gas, a.shard, a.workers)
        total_accepted += len(accepted)
        total_rejected += rejected
        all_tally.update(tally)
        submit_secs += dt
        print(f"  wave {w + 1}/{waves}: accepted {len(accepted)} rejected {rejected} "
              f"in {dt:.2f}s ({len(accepted) / dt:.0f} tx/s submit)")
        if tally:
            print(f"  wave {w + 1} rejections: {fmt_tally(tally)}")
        all_hashes.extend(accepted)
        st = await_finalized(build_rpcs(a), accepted, a.timeout, a.poll_interval)
        finalize_stats.append(st)
        print(f"  wave {w + 1} finalize: success={st['success']} failed={st['failed']} "
              f"pending={st['pending']} t_first={st['t_first']} t_all={st['t_all']} "
              f"via_fallback={st.get('via_fallback', 0)}")
    blast_wall = time.time() - t_blast0
    h1, _ = rpc.call("stell_blockNumber", {})
    h1i = parse_blocknumber(h1) if h1 is not None else -1

    s_ok = sum(s["success"] for s in finalize_stats)
    s_fail = sum(s["failed"] for s in finalize_stats)
    s_pend = sum(s["pending"] for s in finalize_stats)
    s_fb = sum(s.get("via_fallback", 0) for s in finalize_stats)
    t_first_all = next((s["t_first"] for s in finalize_stats if s["t_first"] is not None), None)
    # end-to-end: from first submit to last finalize observed
    e2e_tps = s_ok / blast_wall if blast_wall > 0 else 0.0
    sub_rate = total_accepted / submit_secs if submit_secs > 0 else 0.0

    all_heights = {}
    for s in finalize_stats:
        for h, c in (s.get("heights") or {}).items():
            all_heights[h] = all_heights.get(h, 0) + c
    latest = merged_latest(build_rpcs(a))
    print()
    print("=" * 64)
    print("TPS LOAD SUMMARY")
    print("=" * 64)
    print(f"rpc               : {a.rpc_url} (chain {chain})")
    print(f"accounts / txs    : N={len(pubs)} M={a.txs} (amount={a.amount} gas={a.gas} shard={a.shard})")
    print(f"funding           : {len(nonces)} visible after {fund_wait:.1f}s "
          f"({'direct' if use_direct else 'faucet'})")
    print(f"submission rate   : {sub_rate:.0f} tx/s ({total_accepted} accepted, "
          f"{total_rejected} rejected in {submit_secs:.2f}s)")
    print(f"rejections        : {fmt_tally(dict(all_tally))}")
    print(f"blocks            : {h0i} -> {h1i} ({(h1i - h0i) if h0i >= 0 and h1i >= 0 else '?'} heights)")
    print(f"time-to-finalize  : first {t_first_all}s" if t_first_all is not None else "time-to-finalize  : n/a")
    print(f"end-to-end TPS    : {e2e_tps:.0f} tx/s ({s_ok} success / {s_fail} failed / "
          f"{s_pend} pending over {blast_wall:.1f}s wall, {s_fb} via fallback RPC)")
    print(f"block packing     : {fmt_packing(all_heights)} (from receipts, both nodes)")
    if latest:
        print("recent blocks     : " + ", ".join(
            f"h={b.get('height')} txs={b.get('txs')}" for b in latest[:8]) +
            " (merged A+B, max txs wins)")
    print("nonce discipline  : sequential per account, parallel across accounts "
          "(no NonceGap: arrival order is nonce order)")
    print("bottleneck read   : execution is NOT it (in-process micro-bench, dev release:")
    print("                    Token ~613k tx/s, Native ~26k tx/s).")
    print("                    cap = consensus: 3s round timeout + STELL_MIN_BLOCK_MS")
    print("                    floor (400ms) + MAX_BLOCK_TXS 10k + mempool 10k/256-per-sender.")
    print("=" * 64)
    if a.ssh_host:
        ssh_tail(a.ssh_host, a.ssh_cmd)
    return 0 if s_pend == 0 and total_rejected == 0 else 2

# ------------------------------------------------------------------ cli ---


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Stellereum TPS load harness (RPC, no src changes).")
    p.add_argument("--rpc-url", default=os.environ.get("STELL_RPC_URL", "http://127.0.0.1:8545/"))
    p.add_argument("--rpc-url-b", default=os.environ.get("STELL_RPC_URL_B", ""),
                   help="second node RPC (receipt fallback: receipts are node-local, "
                        "so finalize polling queries both; e.g. http://127.0.0.1:8546/)")
    p.add_argument("--faucet-token", default=os.environ.get("STELL_FAUCET_TOKEN", ""),
                   help="faucet token (STELL_FAUCET_TOKEN); not needed with --direct-fund-key")
    p.add_argument("--direct-fund-key", default=os.environ.get("STELL_DIRECT_FUND_KEY", ""),
                   help="64-hex 32-byte seed: fund test accounts with locally-signed transfers "
                        "instead of stell_faucet (robust when the faucet nonce gaps). "
                        "Fetches the current on-chain nonce via stell_getBalance on the "
                        "derived account, then assigns contiguous nonces.")
    p.add_argument("--api-token", default=os.environ.get("STELL_RPC_AUTH_TOKEN", ""))
    p.add_argument("--accounts", "-N", type=int, default=int(os.environ.get("STELL_N", "10")))
    p.add_argument("--txs", "-M", type=int, default=int(os.environ.get("STELL_M", "1000")))
    p.add_argument("--amount", type=int, default=1)
    # Admission base fee on the live stand is GAS_BASIC_TRANSFER=280_000 nano
    # (src/svm.rs x500; mempool base_fee defaults to it when STELL_MIN_GAS_LIMIT
    # is unset, which it is on the stand). gas_limit < base_fee is rejected
    # with "offered fee is below the base fee", so the default must clear it.
    p.add_argument("--gas", type=int, default=280000,
                   help="gas limit per tx; must be >= chain base fee 280000 (default 280000)")
    p.add_argument("--shard", type=int, default=1,
                   help="must match the node's --shard (default 1 = this stand)")
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--poll-interval", type=float, default=1.0)
    p.add_argument("--timeout", type=float, default=120.0)
    p.add_argument("--ssh-host", default=os.environ.get("STELL_SSH_HOST", ""))
    p.add_argument("--ssh-cmd", default="journalctl -u stell* --no-pager -n 30 2>/dev/null | grep -ai finaliz | tail -20")
    p.add_argument("--run", action="store_true", help="actually fund + blast (default without --run only shows --plan)")
    p.add_argument("--check-only", action="store_true", help="probe RPC method existence, change nothing")
    p.add_argument("--self-test", action="store_true", help="offline sign/encode round-trip, no RPC")
    p.add_argument("--plan", action="store_true", help="dry-run: show derived plan, no RPC")
    p.add_argument("--keys-file", default=os.environ.get("STELL_KEYS_FILE", ""),
                   help="path to hex-JSON keypairs [{private, public}, ...]: saved automatically "
                        "after generation in run_load (fresh run), reloaded with --resume to reuse "
                        "the SAME accounts. Works with --plan (no network) for resume math.")
    p.add_argument("--resume", action="store_true",
                   help="resume mode: load SAME keys from --keys-file, query each account's "
                        "CURRENT on-chain nonce via stell_getBalance, then submit only the "
                        "REMAINDER up to the original per-account target (contiguous nonces, "
                        "200/acct/wave cap). Prints per-account resumed-from/total. "
                        "Skips funding; use with --run. With --plan shows resume math, no network.")
    return p


def main() -> int:
    a = build_parser().parse_args()
    if a.self_test:
        return 0 if do_self_test() else 1
    if a.check_only:
        return 0 if do_check_only(Rpc(a.rpc_url, a.api_token)) else 1
    if not a.run or a.plan:
        do_plan(a)
        return 0
    return run_load(a)


if __name__ == "__main__":
    sys.exit(main())
