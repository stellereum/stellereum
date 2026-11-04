#!/usr/bin/env python3
"""Stellereum TVL probe (testnet, chain 5757).

Reads the live node over JSON-RPC and prints TVL components in nano-STELL
and STELL. Stdlib only (urllib + json). Never sends batches (the node
refuses them with -32600); one POST per method.

Components:
  staking  -- sum over stell_getValidators of stell_stakeOf.total
              (authoritative per-validator ledger read; the power/total_power
              fields are a fallback only). Always included.
  pmm      -- stell_pmmState reserve/treasury snapshot (informational;
              inclusion in TVL is a methodology decision, off by default).
              Enabled with --pmm.
  orderbook-- stell_orderBook depth escrow for a pair id (informational,
              off by default). Enabled with --orderbook PAIR_ID (repeatable).
  bridge   -- NO aggregate escrow endpoint exists (only per-record
              stell_bridgeDeposit / stell_bridgeDispute lookups), so bridge
              escrow cannot be summed here. --bridge-deposit HASH prints one
              deposit record for manual reconciliation; it is NOT added to TVL.

Amounts on the wire are DECIMAL STRINGS in nano-STELL (u64 does not survive
a float): parsed with int(), converted with // and % only.
1 STELL = 1_000_000_000 nano (9 decimals, src/tokenomics.rs).

USD output uses --stell-usd (default 1.0 STUB, printed with a loud warning).
There is no STELL price feed yet; do not present stub-USD as a valuation.

Offline validation (no network):  python3 scripts/tvl_probe.py --self-test
runs the parsers against fixtures, including the live-captured
stell_getValidators shape of 2026-10-14 (extra fragile/fragile_reason
fields, power as decimal nano strings).

Examples:
  python3 scripts/tvl_probe.py
  python3 scripts/tvl_probe.py --rpc http://127.0.0.1:8546 --pmm
  STELL_RPC_URL=https://rpc.stellereum.org python3 scripts/tvl_probe.py
"""

import json
import os
import sys
import urllib.request

NANO_PER_STELL = 1_000_000_000
DEFAULT_RPC = os.environ.get("STELL_RPC_URL", "http://127.0.0.1:8545")


def rpc_call(url, method, params=None, timeout=10):
    """Single JSON-RPC POST. Raises RuntimeError on transport/RPC errors."""
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    ).encode()
    req = urllib.request.Request(
        url, data=body, headers={"content-type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            payload = json.loads(res.read().decode())
    except Exception as exc:  # transport error (refused, timeout, non-JSON)
        raise RuntimeError("transport error on %s: %s" % (method, exc))
    if payload.get("error"):
        raise RuntimeError("rpc %s: %s" % (method, json.dumps(payload["error"])))
    return payload.get("result")


def parse_validators(result):
    """(validators, total_power, quorum) from stell_getValidators.

    Ignores unknown extra fields (live nodes add fragile/fragile_reason).
    Powers are decimal strings in nano-STELL.
    """
    if not isinstance(result, dict):
        raise ValueError("stell_getValidators: result is not an object")
    entries = result.get("validators") or []
    validators = []
    for entry in entries:
        addr = entry.get("validator")
        power = int(entry.get("power", "0"))  # decimal string, never float
        if addr:
            validators.append((addr, power))
    total_power = int(result.get("total_power", "0") or "0")
    quorum = result.get("quorum")
    return validators, total_power, int(quorum) if quorum is not None else None


def parse_stake_total(result):
    """Authoritative bonded total for one validator (stell_stakeOf)."""
    if not isinstance(result, dict):
        raise ValueError("stell_stakeOf: result is not an object")
    return int(result.get("total", "0") or "0")


def fmt_nano(nano):
    """'2000000000000' nano -> '2000 STELL' without float rounding."""
    return "%d.%09d" % (nano // NANO_PER_STELL, nano % NANO_PER_STELL)


def staking_tvl_nano(url, verbose=True):
    """Sum stell_stakeOf.total over the stell_getValidators set.

    Falls back to the power sum only if a per-validator read fails (logged).
    Returns (total_nano, n_validators, used_power_fallback).
    """
    vset = rpc_call(url, "stell_getValidators")
    validators, total_power, quorum = parse_validators(vset)
    if verbose:
        print(
            "validators=%d total_power=%s quorum=%s"
            % (len(validators), fmt_nano(total_power), quorum)
        )
    if not validators:
        return 0, 0, False
    total = 0
    fallback = False
    for addr, power in validators:
        try:
            stake = rpc_call(url, "stell_stakeOf", {"validator": addr})
            total += parse_stake_total(stake)
        except RuntimeError as exc:
            # One bad read must not kill the whole TVL: fall back to the
            # power figure for THIS validator and say so loudly.
            print("WARN: stell_stakeOf failed for %s...: %s" % (addr[:16], exc))
            print("WARN: using its power value as fallback")
            total += power
            fallback = True
    return total, len(validators), fallback


def pmm_snapshot(url):
    """Raw stell_pmmState read (informational; see module docstring)."""
    return rpc_call(url, "stell_pmmState")


def orderbook_depth(url, pair):
    """Raw stell_orderBook read for one pair id (informational)."""
    return rpc_call(url, "stell_orderBook", {"pair": pair})


def bridge_deposit(url, source_tx_hash):
    """One stell_bridgeDeposit record (informational; found may be false)."""
    return rpc_call(url, "stell_bridgeDeposit", {"source_tx_hash": source_tx_hash})


def self_test():
    """Offline parser checks incl. the live-captured 2026-10-14 shape."""
    live = {
        "fragile": False,
        "fragile_reason": None,
        "quorum": "3916354286669",
        "total_power": "5874531430003",
        "validators": [
            {
                "power": "1874531430003",
                "validator": "021776cdf2b3b644e91dbe44fbef4a29f5a8ebf80b01055d3e7cc83a85659694",
            },
            {
                "power": "2000000000000",
                "validator": "9c675ebc6cd20c9226da2fcbf6c167647e4e948b78368f038058b6b419175fcd",
            },
            {
                "power": "2000000000000",
                "validator": "c2313fbaf5c0b1a4921f132bed48772f0d0b788b8f27ad7f96772610996c3361",
            },
        ],
    }
    validators, total_power, quorum = parse_validators(live)
    assert len(validators) == 3, validators
    assert total_power == 5874531430003, total_power
    assert quorum == 3916354286669, quorum
    assert sum(p for _, p in validators) == total_power  # power adds up here
    # Empty / missing set.
    assert parse_validators({"validators": [], "total_power": "0"}) == ([], 0, None)
    assert parse_validators({}) == ([], 0, None)
    # stakeOf shapes (docs/RPC.md section 5).
    assert parse_stake_total(
        {"total": "1000000000", "self_bond": "1000000000", "delegated": "0"}
    ) == 1000000000
    assert parse_stake_total({"total": "0", "self_bond": "0", "delegated": "0"}) == 0
    # Formatting never touches float.
    assert fmt_nano(2000000000000) == "2000.000000000"
    assert fmt_nano(1874531430003) == "1874.531430003"
    assert fmt_nano(1) == "0.000000001"
    # Bad shapes fail loudly, not silently zero.
    for bad in (None, [], "x"):
        try:
            parse_validators(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("parse_validators accepted %r" % (bad,))
    print("SELF_TEST_OK")


def main(argv):
    import argparse

    ap = argparse.ArgumentParser(description="Stellereum TVL probe (testnet 5757)")
    ap.add_argument("--rpc", default=DEFAULT_RPC, help="node URL (default %(default)s)")
    ap.add_argument("--pmm", action="store_true", help="also print stell_pmmState")
    ap.add_argument(
        "--orderbook",
        type=int,
        action="append",
        default=[],
        metavar="PAIR_ID",
        help="also print stell_orderBook for PAIR_ID (repeatable)",
    )
    ap.add_argument(
        "--bridge-deposit",
        default=None,
        metavar="HASH",
        help="print one stell_bridgeDeposit record (informational only)",
    )
    ap.add_argument("--stell-usd", type=float, default=1.0, help="STELL USD stub")
    ap.add_argument("--self-test", action="store_true", help="offline parser checks")
    args = ap.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    print("rpc=%s" % args.rpc)
    chain = rpc_call(args.rpc, "stell_chainId")
    print("chain_id=%s" % chain)
    if chain != 5757:
        print("WARN: expected chain 5757, got %r" % (chain,))

    nano, n, used_fallback = staking_tvl_nano(args.rpc)
    print("staking_validators=%d power_fallback=%s" % (n, used_fallback))
    print("staking_tvl_nano=%d" % nano)
    print("staking_tvl_STELL=%s" % fmt_nano(nano))
    usd = (nano // NANO_PER_STELL) * args.stell_usd
    print("staking_tvl_USD_stub=%.2f  <-- STUB PRICE (STELL_USD=%.4g), NOT a valuation"
          % (usd, args.stell_usd))

    if args.pmm:
        pmm = pmm_snapshot(args.rpc)
        print("pmm_state=%s" % json.dumps(pmm, sort_keys=True))
        print("NOTE: PMM figures are reported, not added to TVL (methodology open).")
    for pair in args.orderbook:
        book = orderbook_depth(args.rpc, pair)
        bids = sum(int(l.get("available_nano_stell", 0)) for l in book.get("bids", []))
        print("orderbook_pair_%d_locked_bid_nano=%d (%s STELL)"
              % (pair, bids, fmt_nano(bids)))
        print("NOTE: orderbook escrow is reported, not added to TVL (methodology open).")
    if args.bridge_deposit:
        rec = bridge_deposit(args.rpc, args.bridge_deposit)
        print("bridge_deposit=%s" % json.dumps(rec, sort_keys=True))
        print("NOTE: bridge escrow has no aggregate RPC read; record shown for manual reconciliation only.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
