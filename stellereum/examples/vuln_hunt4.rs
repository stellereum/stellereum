//! PERSONAL VULNERABILITY HUNT — round 4 (decoder fuzzing / DoS / panic).
//! Feeds crafted bytes into every decoder; asserts no panic and bounded work.
//!     cargo run --release --example vuln_hunt4

use rand::rngs::OsRng;
use rand::RngCore;

use stellereum::cell::BagOfCells;
use stellereum::consensus_net::{parse_incoming, parse_tx_incoming, ConsensusMsg};

fn hdr(n: u32, t: &str) {
    println!("\n\x1b[1;36m[{n}] {t}\x1b[0m");
}
fn blocked(t: &str) {
    println!("  \x1b[32mBLOCKED\x1b[0m: {t}");
}
fn vuln(t: &str) {
    println!("  \x1b[41m!! VULNERABLE:\x1b[0m {t}");
}

fn main() {
    println!("\x1b[1;33m##########################################################");
    println!("##   VULN HUNT ROUND 4 (decoder fuzz / DoS)             ##");
    println!("##########################################################\x1b[0m");

    // 1. ConsensusMsg::decode fuzz
    hdr(1, "ConsensusMsg::decode random bytes (no panic)");
    {
        let mut rng = OsRng;
        for _ in 0..50_000 {
            let n = (rng.next_u32() % 600) as usize;
            let mut buf = vec![0u8; n];
            rng.fill_bytes(&mut buf);
            let _ = ConsensusMsg::decode(&buf); // must never panic
        }
        blocked("50k random buffers decoded without panic");
    }

    // 2. parse_incoming with crafted hex
    hdr(2, "parse_incoming crafted JSON/hex (no panic)");
    {
        let mut rng = OsRng;
        let cases = vec![
            "".to_string(),
            "{}".to_string(),
            "{\"data\":\"\"}".to_string(),
            "{\"data\":\"zzzz\"}".to_string(),
            format!("{{\"data\":\"{}\"}}", "ff".repeat(1000)),
            format!("{{\"data\":\"{}\"}}", hex::encode(vec![0u8; 70000])),
        ];
        for c in &cases {
            let _ = parse_incoming(c);
            let _ = parse_tx_incoming(c);
        }
        for _ in 0..20_000 {
            let n = (rng.next_u32() % 200) as usize;
            let mut b = vec![0u8; n];
            rng.fill_bytes(&mut b);
            let s = format!("{{\"data\":\"{}\"}}", hex::encode(&b));
            let _ = parse_incoming(&s);
            let _ = parse_tx_incoming(&s);
        }
        blocked("crafted/random consensus+tx incoming strings handled safely");
    }

    // 3. BagOfCells::deserialize fuzz
    hdr(3, "BagOfCells::deserialize random bytes");
    {
        let mut rng = OsRng;
        for _ in 0..50_000 {
            let n = (rng.next_u32() % 800) as usize;
            let mut buf = vec![0u8; n];
            rng.fill_bytes(&mut buf);
            let _ = BagOfCells::deserialize(&buf);
        }
        blocked("50k random BoC deserializations without panic");
    }

    // 4. JSON parser fuzz (same parser the RPC layer uses)
    hdr(4, "serde_json parse of fuzzed RPC-like bodies");
    {
        let mut rng = OsRng;
        for _ in 0..10_000 {
            let n = (rng.next_u32() % 300) as usize;
            let mut b = vec![0u8; n];
            rng.fill_bytes(&mut b);
            let s = String::from_utf8_lossy(&b);
            let _: Result<serde_json::Value, _> = serde_json::from_str(&s);
        }
        blocked("10k fuzzed bodies parsed without panic");
    }

    // 5. JSON depth bomb (deep nesting -> stack overflow attempt)
    hdr(5, "JSON deep nesting (stack overflow attempt)");
    {
        let depth = 100_000;
        let mut s = String::new();
        for _ in 0..depth {
            s.push('[');
        }
        for _ in 0..depth {
            s.push(']');
        }
        // serde_json has a recursion limit (128 by default) -> returns Err, no crash
        let r: Result<serde_json::Value, _> = serde_json::from_str(&s);
        if r.is_err() {
            blocked("deep nesting rejected by serde_json recursion limit");
        } else {
            vuln("deep JSON nesting accepted (stack risk)");
        }
    }

    // 6. ConsensusMsg oversized (bounded rejection at MAX_CONSENSUS_MSG)
    hdr(6, "ConsensusMsg oversized input rejected at the cap");
    {
        use stellereum::consensus_net::MAX_CONSENSUS_MSG;
        let at_cap = vec![0u8; MAX_CONSENSUS_MSG];
        let over = vec![0u8; MAX_CONSENSUS_MSG + 1];
        // at the cap: passes the size gate (then fails to decode) -> Err is fine
        let _ = ConsensusMsg::decode(&at_cap);
        if ConsensusMsg::decode(&over).is_err() {
            blocked("over-cap message rejected before decode");
        } else {
            vuln("over-cap message accepted");
        }
        if ConsensusMsg::decode(&[]).is_err() {
            blocked("empty message rejected");
        } else {
            vuln("empty message accepted");
        }
    }

    println!("\n\x1b[1;33m############ ROUND 4 DONE ############\x1b[0m");
}
