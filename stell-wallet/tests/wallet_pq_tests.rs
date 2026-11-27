//! Comprehensive Test Suite for Post-Quantum Address and Key Utilities in Stell-Wallet
//!
//! Verifies:
//! 1. Address derivation (`derive_pq_address`) for all 4 schemes defined in Stellereum PQ-BFT v4:
//!    - Ed25519 (0x01)
//!    - Falcon-512 (0x02)
//!    - ML-DSA-44 (0x03)
//!    - Hybrid Dual-Sig (0x04)
//! 2. Exact specification compliance:
//!    `address = BLAKE3("STL_ADDR_V4" || scheme_id || public_key_bytes || salt)`
//! 3. Cryptographic isolation & domain separation (scheme IDs, salts, keys).
//! 4. CLI command parsing, argument gates, and output formats for `pq-address` and `pq-generate`.
//! 5. Secure memory scrubbing (zeroization on drop, no private key leaks).
//! 6. Address compatibility with standard 32-byte hex addresses and visual checksum format.

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/rpc.rs"]
mod rpc;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/security.rs"]
mod security;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/client.rs"]
mod client;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/pq.rs"]
mod pq;

use client::LightClient;
use pq::{
    derive_pq_address, format_address_with_visual_checksum, format_pq_address,
    format_pq_address_hex, generate_sample_keypair, PqGenScheme, PqScheme, PqSignatureEnvelope,
    DEFAULT_SALT, ED25519_PUBKEY_LEN, FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN, HYBRID_PUBKEY_LEN,
    MLDSA44_PUBKEY_LEN, PQ_ADDRESS_DOMAIN, PQ_ENVELOPE_MAGIC,
};
use std::process::Command;
use stellereum::sharding::Transaction;

// =============================================================================
// Helper: reference manual implementation of Stellereum PQ-BFT v4 address rule
// =============================================================================
fn reference_pq_address(scheme_id: u8, pubkey: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"STL_ADDR_V4");
    hasher.update(&[scheme_id]);
    hasher.update(pubkey);
    hasher.update(salt);
    *hasher.finalize().as_bytes()
}

fn parse_hex32(hex_str: &str) -> Result<[u8; 32], String> {
    let clean = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
    let bytes = hex::decode(clean).map_err(|e| format!("Invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// =============================================================================
// 1. Address derivation tests for all 4 schemes
// =============================================================================

#[test]
fn test_derive_pq_address_all_four_schemes_against_spec() {
    let salt: [u8; 16] = *b"test_salt_16byte";

    // 1. Scheme 1: Ed25519 (32 bytes public key)
    let ed_pub = [0x11u8; 32];
    let addr_ed = derive_pq_address(PqScheme::Ed25519, &ed_pub, &salt);
    let expected_ed = reference_pq_address(1, &ed_pub, &salt);
    assert_eq!(
        addr_ed, expected_ed,
        "Ed25519 address must match BLAKE3 spec"
    );
    assert_eq!(addr_ed.len(), 32);

    // 2. Scheme 2: Falcon-512 (897 bytes public key)
    let falcon_pub = vec![0x22u8; FALCON512_PUBKEY_LEN];
    let addr_falcon = derive_pq_address(PqScheme::Falcon512, &falcon_pub, &salt);
    let expected_falcon = reference_pq_address(2, &falcon_pub, &salt);
    assert_eq!(
        addr_falcon, expected_falcon,
        "Falcon-512 address must match BLAKE3 spec"
    );
    assert_eq!(addr_falcon.len(), 32);

    // 3. Scheme 3: ML-DSA-44 (1312 bytes public key)
    let mldsa_pub = vec![0x33u8; MLDSA44_PUBKEY_LEN];
    let addr_mldsa = derive_pq_address(PqScheme::MlDsa44, &mldsa_pub, &salt);
    let expected_mldsa = reference_pq_address(3, &mldsa_pub, &salt);
    assert_eq!(
        addr_mldsa, expected_mldsa,
        "ML-DSA-44 address must match BLAKE3 spec"
    );
    assert_eq!(addr_mldsa.len(), 32);

    // 4. Scheme 4: Hybrid (929 bytes public key)
    let hybrid_pub = vec![0x44u8; HYBRID_PUBKEY_LEN];
    let addr_hybrid = derive_pq_address(PqScheme::Hybrid, &hybrid_pub, &salt);
    let expected_hybrid = reference_pq_address(4, &hybrid_pub, &salt);
    assert_eq!(
        addr_hybrid, expected_hybrid,
        "Hybrid address must match BLAKE3 spec"
    );
    assert_eq!(addr_hybrid.len(), 32);
}

#[test]
fn test_scheme_domain_separation_prevents_cross_scheme_collisions() {
    let dummy_key = [0x5au8; 64];
    let salt = [0x00u8; 16];

    let addr_ed = derive_pq_address(PqScheme::Ed25519, &dummy_key, &salt);
    let addr_falcon = derive_pq_address(PqScheme::Falcon512, &dummy_key, &salt);
    let addr_mldsa = derive_pq_address(PqScheme::MlDsa44, &dummy_key, &salt);
    let addr_hybrid = derive_pq_address(PqScheme::Hybrid, &dummy_key, &salt);

    // All addresses must be strictly distinct due to scheme_id injection
    let addresses = [addr_ed, addr_falcon, addr_mldsa, addr_hybrid];
    for i in 0..addresses.len() {
        for j in (i + 1)..addresses.len() {
            assert_ne!(
                addresses[i],
                addresses[j],
                "Schemes {} and {} collided on identical input!",
                i + 1,
                j + 1
            );
        }
    }
}

#[test]
fn test_salt_and_pubkey_isolation() {
    let key1 = [0x01u8; 32];
    let key2 = [0x02u8; 32];
    let salt1 = [0xaa; 16];
    let salt2 = [0xbb; 16];

    let a1 = derive_pq_address(PqScheme::Ed25519, &key1, &salt1);
    let a2 = derive_pq_address(PqScheme::Ed25519, &key1, &salt2);
    let a3 = derive_pq_address(PqScheme::Ed25519, &key2, &salt1);

    assert_ne!(a1, a2, "Different salts must yield different addresses");
    assert_ne!(a1, a3, "Different pubkeys must yield different addresses");
    assert_ne!(a2, a3);
}

// =============================================================================
// 2. Scheme metadata, properties, and parsing
// =============================================================================

#[test]
fn test_scheme_metadata_and_discriminants() {
    assert_eq!(PqScheme::Ed25519.id(), 1);
    assert_eq!(PqScheme::Falcon512.id(), 2);
    assert_eq!(PqScheme::MlDsa44.id(), 3);
    assert_eq!(PqScheme::Hybrid.id(), 4);

    assert_eq!(PqScheme::from_id(1).unwrap(), PqScheme::Ed25519);
    assert_eq!(PqScheme::from_id(2).unwrap(), PqScheme::Falcon512);
    // Audit HIGH-2: 0x03 fail-closed like the node.
    assert!(PqScheme::from_id(3).is_err());
    assert_eq!(PqScheme::from_id(4).unwrap(), PqScheme::Hybrid);
    assert!(PqScheme::from_id(0).is_err());
    assert!(PqScheme::from_id(5).is_err());

    assert_eq!(PqScheme::Ed25519.pubkey_size(), ED25519_PUBKEY_LEN);
    assert_eq!(PqScheme::Falcon512.pubkey_size(), FALCON512_PUBKEY_LEN);
    assert_eq!(PqScheme::MlDsa44.pubkey_size(), MLDSA44_PUBKEY_LEN);
    assert_eq!(PqScheme::Hybrid.pubkey_size(), HYBRID_PUBKEY_LEN);

    assert!(!PqScheme::Ed25519.is_post_quantum());
    assert!(PqScheme::Falcon512.is_post_quantum());
    assert!(PqScheme::MlDsa44.is_post_quantum());
    assert!(PqScheme::Hybrid.is_post_quantum());

    assert_eq!(PQ_ADDRESS_DOMAIN, b"STL_ADDR_V4");
    assert_eq!(PqScheme::from(PqGenScheme::Falcon512), PqScheme::Falcon512);
    assert_eq!(PqScheme::from(PqGenScheme::MlDsa44), PqScheme::MlDsa44);
    assert_eq!(PqScheme::from(PqGenScheme::Hybrid), PqScheme::Hybrid);
}

#[test]
fn test_scheme_from_str_parsing() {
    assert_eq!("ed25519".parse::<PqScheme>().unwrap(), PqScheme::Ed25519);
    assert_eq!(
        "falcon512".parse::<PqScheme>().unwrap(),
        PqScheme::Falcon512
    );
    assert_eq!(
        "falcon-512".parse::<PqScheme>().unwrap(),
        PqScheme::Falcon512
    );
    // Audit HIGH-2: ML-DSA-44 is fail-closed DISABLED (mirrors node
    // `from_id(3)` refusal) — parse paths must refuse it loudly.
    for disabled in ["mldsa44", "ml-dsa-44", "3"] {
        let err = disabled.parse::<PqScheme>().unwrap_err();
        assert!(err.to_lowercase().contains("disabled"));
        assert!(err.contains("falcon512") && err.contains("hybrid"));
    }
    assert_eq!("hybrid".parse::<PqScheme>().unwrap(), PqScheme::Hybrid);
    assert!("not-a-scheme".parse::<PqScheme>().is_err());
}

// =============================================================================
// 3. Sample keypair generation and memory security
// =============================================================================

#[test]
fn test_sample_keypair_generation_dimensions_and_derivation() {
    for scheme in [PqScheme::Falcon512, PqScheme::MlDsa44, PqScheme::Hybrid] {
        let keypair = generate_sample_keypair(scheme);
        assert_eq!(keypair.scheme(), scheme);
        assert_eq!(keypair.public_key().len(), scheme.pubkey_size());
        assert_eq!(keypair.public_key_hex().len(), scheme.pubkey_size() * 2);

        // Address derived via keypair method matches derive_pq_address directly
        let addr1 = keypair.derive_address(&DEFAULT_SALT);
        let addr2 = derive_pq_address(scheme, keypair.public_key(), &DEFAULT_SALT);
        assert_eq!(addr1, addr2);

        // Two independent generations produce unique keys
        let keypair2 = generate_sample_keypair(scheme);
        assert_ne!(keypair.public_key(), keypair2.public_key());
    }
}

#[test]
fn test_secure_memory_scrubbing_and_no_leak() {
    let kp = generate_sample_keypair(PqScheme::Falcon512);
    let debug_repr = format!("{:?}", kp);
    assert!(debug_repr.contains("[REDACTED_SECURE]"));
    assert!(!debug_repr.contains("seed"));
    assert!(!debug_repr.contains("private"));
}

// =============================================================================
// 4. Address compatibility with standard 32-byte hex addresses
// =============================================================================

#[test]
fn test_address_compatibility_with_standard_hex() {
    for scheme in [
        PqScheme::Ed25519,
        PqScheme::Falcon512,
        PqScheme::MlDsa44,
        PqScheme::Hybrid,
    ] {
        let kp = generate_sample_keypair(scheme);
        let addr_bytes = kp.derive_address(&DEFAULT_SALT);
        let addr_hex = format_pq_address_hex(&addr_bytes);

        // Standard address length is exactly 64 hex characters (32 bytes)
        assert_eq!(addr_hex.len(), 64);
        assert!(addr_hex.chars().all(|c| c.is_ascii_hexdigit()));

        // Parse back with standard wallet hex32 parser
        let parsed = parse_hex32(&addr_hex).expect("Must parse as standard 32-byte wallet address");
        assert_eq!(parsed, addr_bytes);

        // Visual checksum formatting preserves original characters
        let visual = format_address_with_visual_checksum(&addr_hex);
        assert!(visual.contains(&addr_hex[..8]));
        assert!(visual.contains(&addr_hex[56..]));

        let pq_visual = format_pq_address(&addr_bytes);
        assert_eq!(visual, pq_visual);
    }
}

// =============================================================================
// 5. CLI command parsing and output format tests (via `stell` binary)
// =============================================================================

#[test]
fn test_cli_pq_address_help() {
    let bin = env!("CARGO_BIN_EXE_stell");
    let out = Command::new(bin)
        .args(["pq-address", "--help"])
        .output()
        .expect("exec");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("pq-address"));
    assert!(stdout.contains("--scheme"));
    assert!(stdout.contains("falcon512"));
    assert!(stdout.contains("mldsa44"));
    assert!(stdout.contains("hybrid"));
    assert!(stdout.contains("ed25519"));
}

#[test]
fn test_cli_pq_generate_help() {
    let bin = env!("CARGO_BIN_EXE_stell");
    let out = Command::new(bin)
        .args(["pq-generate", "--help"])
        .output()
        .expect("exec");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("pq-generate"));
    assert!(stdout.contains("--scheme"));
    assert!(stdout.contains("falcon512"));
    assert!(stdout.contains("mldsa44"));
    assert!(stdout.contains("hybrid"));
}

#[test]
fn test_cli_pq_generate_execution_all_schemes() {
    let bin = env!("CARGO_BIN_EXE_stell");

    let out = Command::new(bin)
        .args(["pq-generate", "--scheme", "falcon512"])
        .output()
        .expect("exec");
    assert!(out.status.success(), "Failed for scheme falcon512");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("STELLEREUM POST-QUANTUM KEY GENERATOR"));
    assert!(stdout.contains("Scheme ID:"));
    assert!(stdout.contains("Public Key Size:"));
    assert!(stdout.contains("Public Key (Hex):"));
    assert!(stdout.contains("Derived PQ Address:"));
    assert!(stdout.contains("Raw Address Hex:"));
    assert!(stdout.contains("Private keys are safely held in scrubbed memory"));

    let raw_hex_line = stdout
        .lines()
        .find(|l| l.contains("Raw Address Hex:"))
        .expect("must contain raw address hex line");
    let hex_part = raw_hex_line.split(':').nth(1).unwrap().trim();
    assert_eq!(hex_part.len(), 64);
    assert!(parse_hex32(hex_part).is_ok());

    // FULL-PQ: disabled/legacy schemes must refuse generation fail-closed.
    for refused_scheme in ["mldsa44", "hybrid"] {
        let out = Command::new(bin)
            .args(["pq-generate", "--scheme", refused_scheme])
            .output()
            .expect("exec");
        assert!(
            !out.status.success(),
            "{refused_scheme} generation must refuse fail-closed under FULL-PQ"
        );
    }
}

#[test]
fn test_cli_pq_address_execution_all_schemes() {
    let bin = env!("CARGO_BIN_EXE_stell");

    let out = Command::new(bin)
        .args(["pq-address", "--scheme", "falcon512"])
        .output()
        .expect("exec");
    assert!(out.status.success(), "Failed for scheme falcon512");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("STELLEREUM POST-QUANTUM ADDRESS DERIVATION"));
    assert!(stdout.contains("Scheme:"));
    assert!(stdout.contains("Public Key Size:"));
    assert!(stdout.contains("Derived PQ Address:"));
    assert!(stdout.contains("Raw Address Hex:"));

    // FULL-PQ: disabled/legacy schemes refused even for address derivation.
    for refused_scheme in ["mldsa44", "hybrid", "ed25519"] {
        let out = Command::new(bin)
            .args(["pq-address", "--scheme", refused_scheme])
            .output()
            .expect("exec");
        assert!(
            !out.status.success(),
            "{refused_scheme} address derivation must refuse fail-closed under FULL-PQ"
        );
    }
}

#[test]
fn test_cli_pq_address_with_explicit_pubkey_and_salt() {
    let bin = env!("CARGO_BIN_EXE_stell");
    let test_pubkey = "aa".repeat(32); // 32 bytes hex
    let test_salt = "11".repeat(16); // 16 bytes hex

    let out = Command::new(bin)
        .args([
            "pq-address",
            "--scheme",
            "ed25519",
            "--pubkey",
            &test_pubkey,
            "--salt",
            &test_salt,
        ])
        .output()
        .expect("exec");
    assert!(out.status.success());

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Public Key Source:    Provided"));

    // Verify derived address matches manual expectation
    let pub_bytes = hex::decode(&test_pubkey).unwrap();
    let salt_bytes: [u8; 16] = hex::decode(&test_salt).unwrap().try_into().unwrap();
    let expected_addr = derive_pq_address(PqScheme::Ed25519, &pub_bytes, &salt_bytes);
    let expected_hex = hex::encode(expected_addr);

    assert!(stdout.contains(&expected_hex));
}

#[test]
fn test_cli_pq_generate_rejects_ed25519() {
    let bin = env!("CARGO_BIN_EXE_stell");
    let out = Command::new(bin)
        .args(["pq-generate", "--scheme", "ed25519"])
        .output()
        .expect("exec");

    // Must fail because ed25519 is classical and excluded from pq-generate schemes
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid value 'ed25519'") || stderr.contains("possible values"));
}

#[test]
fn test_cli_rejects_invalid_scheme_and_bad_arguments() {
    let bin = env!("CARGO_BIN_EXE_stell");

    // 1. Missing required --scheme argument
    let out_no_scheme = Command::new(bin)
        .args(["pq-address"])
        .output()
        .expect("exec");
    assert_eq!(out_no_scheme.status.code(), Some(2));

    // 2. Invalid scheme name
    let out_bad_scheme = Command::new(bin)
        .args(["pq-address", "--scheme", "rsa4096"])
        .output()
        .expect("exec");
    assert_eq!(out_bad_scheme.status.code(), Some(2));

    // 3. Bad hex for pubkey
    let out_bad_hex = Command::new(bin)
        .args([
            "pq-address",
            "--scheme",
            "ed25519",
            "--pubkey",
            "not-hex-at-all",
        ])
        .output()
        .expect("exec");
    assert!(!out_bad_hex.status.success());
    let err_msg = format!(
        "{}{}",
        String::from_utf8_lossy(&out_bad_hex.stdout),
        String::from_utf8_lossy(&out_bad_hex.stderr)
    );
    assert!(err_msg.contains("Invalid public key hex"));

    // 4. Bad salt size
    let out_bad_salt = Command::new(bin)
        .args(["pq-address", "--scheme", "falcon512", "--salt", "1234"])
        .output()
        .expect("exec");
    assert!(!out_bad_salt.status.success());
    let err_msg = format!(
        "{}{}",
        String::from_utf8_lossy(&out_bad_salt.stdout),
        String::from_utf8_lossy(&out_bad_salt.stderr)
    );
    assert!(err_msg.contains("16 bytes") || err_msg.contains("32 hex"));
}

// =============================================================================
// 6. Post-Quantum Transfer & Transaction Construction Tests
// =============================================================================

#[test]
fn test_tx_construction_explicit_falcon512_activation_envelope() {
    let kp = generate_sample_keypair(PqScheme::Falcon512);
    let to = [0x55u8; 32];
    let amount = 10_000_000_000; // 10 STELL
    let nonce = 0;
    let shard = 1;
    let is_activation = true;

    let tx = LightClient::build_pq_transfer_tx(&kp, to, amount, nonce, shard, is_activation)
        .expect("Falcon-512 transfer");

    let from_addr = kp.derive_address(&DEFAULT_SALT);
    assert_eq!(
        tx.from, from_addr,
        "Sender address must match derived PQ address"
    );
    assert_eq!(tx.to, to);
    assert_eq!(tx.amount, amount);
    assert_eq!(tx.nonce, nonce);
    assert_eq!(tx.source_shard, shard);
    assert_eq!(tx.target_shard, shard);
    assert_eq!(tx.gas_limit, stellereum::svm::GAS_BASIC_TRANSFER);

    // Frame markers
    assert!(tx.is_pq(), "Transaction must report is_pq = true");
    assert!(
        tx.is_pq_activation(),
        "Activation tx must carry explicit pubkey"
    );
    assert!(!tx.is_pq_implicit(), "Activation tx must not be implicit");
    assert!(
        tx.signature.starts_with(PQ_ENVELOPE_MAGIC),
        "Signature wire must start with PQ1"
    );

    // Decode and verify canonical salted PQ1 envelope
    let envelope = stellereum::sharding::PqSignatureEnvelope::decode_canonical(&tx.signature)
        .expect("Valid canonical PQ1 envelope");
    assert_eq!(envelope.scheme, stellereum::post_quantum::PqScheme::Falcon512);
    assert!(!envelope.is_implicit, "Envelope must be explicit");
    assert_eq!(envelope.pubkey, Some(kp.public_key().to_vec()));
    assert_eq!(envelope.salt, DEFAULT_SALT);
    assert_eq!(envelope.signature_bytes.len(), FALCON512_SIG_LEN);

    // Self-verification against global implicit registry
    assert!(
        tx.verify_signature(),
        "Explicit Falcon-512 activation transaction signature must verify"
    );

    // Verify key was registered into implicit registry during verification
    let registry = Transaction::global_implicit_registry();
    let looked_up = registry
        .lookup(&from_addr)
        .expect("Key must be registered after explicit tx");
    assert_eq!(looked_up.0, stellereum::post_quantum::PqScheme::Falcon512);
    assert_eq!(looked_up.1, kp.public_key());
}

#[test]
fn test_tx_construction_implicit_falcon512_envelope() {
    let kp = generate_sample_keypair(PqScheme::Falcon512);
    let from_addr = kp.derive_address(&DEFAULT_SALT);
    let to = [0x66u8; 32];
    let amount = 5_000_000_000; // 5 STELL
    let nonce = 1;
    let shard = 1;
    let is_activation = false;

    // Pre-register key into global implicit registry (simulating steady-state spend after Tx #1)
    let registry = Transaction::global_implicit_registry();
    registry
        .register(
            from_addr,
            kp.scheme().into(),
            kp.public_key(),
            &DEFAULT_SALT,
        )
        .expect("Pre-registration must succeed");

    let tx = LightClient::build_pq_transfer_tx(&kp, to, amount, nonce, shard, is_activation)
        .expect("Falcon-512 transfer");

    assert_eq!(tx.from, from_addr);
    assert_eq!(tx.to, to);
    assert_eq!(tx.amount, amount);
    assert_eq!(tx.nonce, nonce);
    assert_eq!(tx.gas_limit, stellereum::svm::GAS_BASIC_TRANSFER);

    // Frame markers
    assert!(tx.is_pq());
    assert!(!tx.is_pq_activation(), "Implicit tx must not be activation");
    assert!(
        tx.is_pq_implicit(),
        "Implicit tx must report is_pq_implicit = true"
    );
    assert!(tx.signature.starts_with(PQ_ENVELOPE_MAGIC));

    // Decode and verify canonical implicit PQ1 envelope
    let envelope = stellereum::sharding::PqSignatureEnvelope::decode_canonical(&tx.signature)
        .expect("Valid canonical PQ1 envelope");
    assert_eq!(envelope.scheme, stellereum::post_quantum::PqScheme::Falcon512);
    assert!(envelope.is_implicit, "Envelope must be implicit");
    assert_eq!(
        envelope.pubkey, None,
        "Implicit envelope omits public key from wire"
    );
    assert_eq!(envelope.signature_bytes.len(), FALCON512_SIG_LEN);

    // Transaction signature verification succeeds using pre-registered key
    assert!(
        tx.verify_signature(),
        "Implicit Falcon-512 steady-state transaction signature must verify against registry"
    );
}

#[test]
fn test_tx_construction_hybrid_activation_and_implicit_envelopes() {
    // FULL-PQ: legacy Hybrid keys are refused when constructing consensus txs.
    let kp = generate_sample_keypair(PqScheme::Hybrid);
    let to = [0x77u8; 32];
    let amount = 2_500_000_000;
    assert!(LightClient::build_pq_transfer_tx(&kp, to, amount, 0, 1, true).is_err());
    assert!(LightClient::build_pq_transfer_tx(&kp, to, amount, 1, 1, false).is_err());
}

#[test]
fn test_deterministic_keypair_derivation_from_seed() {
    let seed = [42u8; 32];
    let kp_falcon1 = pq::PqKeyPair::from_seed(PqScheme::Falcon512, &seed);
    let kp_falcon2 = pq::PqKeyPair::from_seed(PqScheme::Falcon512, &seed);

    assert_eq!(kp_falcon1.public_key(), kp_falcon2.public_key());
    assert_eq!(
        kp_falcon1.derive_address(&DEFAULT_SALT),
        kp_falcon2.derive_address(&DEFAULT_SALT)
    );

    let msg = b"Stellereum PQ Transfer Signing Test";
    let sig1 = kp_falcon1.sign(msg);
    let sig2 = kp_falcon2.sign(msg);
    // Node security invariant (stellereum post_quantum tests): FIPS 206 signing
    // is randomized even with a caller seed — sigs from the same key MUST both
    // verify and MUST NOT be equal (parallelepiped-leak fix). Key derivation
    // above stays deterministic; signature equality must not be asserted.
    assert_eq!(sig1.len(), FALCON512_SIG_LEN);
    assert_eq!(sig2.len(), FALCON512_SIG_LEN);

    assert!(pq::verify_pq_signature(
        PqScheme::Falcon512.into(),
        kp_falcon1.public_key(),
        msg,
        &sig1
    ));
    assert!(pq::verify_pq_signature(
        PqScheme::Falcon512.into(),
        kp_falcon2.public_key(),
        msg,
        &sig2
    ));

    // FULL-PQ: Hybrid deterministic key derivation succeeds, while converting to consensus PqScheme refuses legacy Hybrid.
    let kp_hyb1 = pq::PqKeyPair::from_seed(PqScheme::Hybrid, &seed);
    let kp_hyb2 = pq::PqKeyPair::from_seed(PqScheme::Hybrid, &seed);
    assert_eq!(kp_hyb1.public_key(), kp_hyb2.public_key());
    assert!(PqScheme::Hybrid.try_consensus_scheme().is_err());
}

// =============================================================================
// 7. CLI Command Parsing and Argument Validation for `pq-transfer`
// =============================================================================

#[test]
fn test_cli_pq_transfer_help() {
    let bin = env!("CARGO_BIN_EXE_stell");
    let out = Command::new(bin)
        .args(["pq-transfer", "--help"])
        .output()
        .expect("exec");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("pq-transfer"));
    assert!(stdout.contains("<TO>"));
    assert!(stdout.contains("<AMOUNT>"));
    assert!(stdout.contains("--scheme"));
    assert!(stdout.contains("falcon512"));
    assert!(stdout.contains("hybrid"));
    assert!(stdout.contains("--activation"));
    assert!(stdout.contains("--dry-run"));
}

#[test]
fn test_cli_pq_transfer_argument_validation_and_rejections() {
    let bin = env!("CARGO_BIN_EXE_stell");
    let valid_to = "aa".repeat(32);

    // 1. Missing arguments entirely
    let out_no_args = Command::new(bin)
        .args(["pq-transfer"])
        .output()
        .expect("exec");
    assert_eq!(out_no_args.status.code(), Some(2));

    // 2. Missing required --scheme
    let out_no_scheme = Command::new(bin)
        .args(["pq-transfer", &valid_to, "10.0"])
        .output()
        .expect("exec");
    assert_eq!(out_no_scheme.status.code(), Some(2));

    // 3. Invalid scheme name
    let out_bad_scheme = Command::new(bin)
        .args(["pq-transfer", &valid_to, "10.0", "--scheme", "rsa4096"])
        .output()
        .expect("exec");
    assert_eq!(out_bad_scheme.status.code(), Some(2));

    // 4. Ed25519 rejected for pq-transfer (must use falcon512 or hybrid)
    let out_ed_scheme = Command::new(bin)
        .args(["pq-transfer", &valid_to, "10.0", "--scheme", "ed25519"])
        .output()
        .expect("exec");
    assert_eq!(out_ed_scheme.status.code(), Some(2));

    // 5. ML-DSA-44 rejected for pq-transfer (only falcon512 and hybrid are allowed)
    let out_mldsa_scheme = Command::new(bin)
        .args(["pq-transfer", &valid_to, "10.0", "--scheme", "mldsa44"])
        .output()
        .expect("exec");
    assert_eq!(out_mldsa_scheme.status.code(), Some(2));

    // 6. Bad recipient hex length
    let out_bad_to = Command::new(bin)
        .args([
            "pq-transfer",
            "deadbeef",
            "10.0",
            "--scheme",
            "falcon512",
            "--dry-run",
            "--password",
            "testpass",
        ])
        .output()
        .expect("exec");
    assert!(!out_bad_to.status.success());

    // 7. Bad amount format
    let out_bad_amt = Command::new(bin)
        .args([
            "pq-transfer",
            &valid_to,
            "-5.0",
            "--scheme",
            "falcon512",
            "--dry-run",
            "--password",
            "testpass",
        ])
        .output()
        .expect("exec");
    assert!(!out_bad_amt.status.success());
}

// =============================================================================
// 8. CLI Dry-Run Execution Tests
// =============================================================================

fn create_temp_wallet(bin: &str, password: &str) -> std::path::PathBuf {
    let tmp = std::env::temp_dir().join(format!(
        "stell_pq_test_wallet_{}_{}.json",
        std::process::id(),
        rand::random::<u64>()
    ));
    let out = Command::new(bin)
        .args([
            "--wallet",
            tmp.to_str().unwrap(),
            "new",
            "--password",
            password,
        ])
        .output()
        .expect("create test wallet");
    assert!(
        out.status.success(),
        "Creating temporary wallet must succeed"
    );
    tmp
}

#[test]
fn test_cli_pq_transfer_dry_run_falcon512_explicit() {
    let bin = env!("CARGO_BIN_EXE_stell");
    let password = "test_password_12345";
    let wallet_path = create_temp_wallet(bin, password);
    let to_hex = "bb".repeat(32);

    let out = Command::new(bin)
        .args([
            "--wallet",
            wallet_path.to_str().unwrap(),
            "pq-transfer",
            &to_hex,
            "15.5",
            "--scheme",
            "falcon512",
            "--activation",
            "--dry-run",
            "--password",
            password,
        ])
        .output()
        .expect("exec dry run");

    let _ = std::fs::remove_file(&wallet_path);
    assert!(out.status.success(), "Dry run must succeed");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("POST-QUANTUM TRANSACTION DRY-RUN (NOT BROADCAST)"));
    assert!(stdout.contains("DRY RUN"));
    assert!(stdout.contains("Falcon-512"));
    assert!(stdout.contains("Explicit Carrier (Tx #1 Account Activation)"));
    assert!(stdout.contains("15.5 STELL"));
    assert!(stdout.contains("Envelope Format: PQ1"));
    assert!(stdout.contains("Carried PubKey:  897 bytes"));
    assert!(stdout.contains("Computed TxHash:"));
    assert!(stdout.contains("✅ Valid PQ1 Frame"));
    assert!(stdout.contains("✅ Signature Verifies"));
}

#[test]
fn test_cli_pq_transfer_dry_run_falcon512_always_explicit() {
    let bin = env!("CARGO_BIN_EXE_stell");
    let password = "test_password_12345";
    let wallet_path = create_temp_wallet(bin, password);
    let to_hex = "cc".repeat(32);

    let out = Command::new(bin)
        .args([
            "--wallet",
            wallet_path.to_str().unwrap(),
            "pq-transfer",
            &to_hex,
            "8.0",
            "--scheme",
            "falcon512",
            "--dry-run",
            "--password",
            password,
        ])
        .output()
        .expect("exec dry run");

    let _ = std::fs::remove_file(&wallet_path);
    assert!(out.status.success(), "Dry run must succeed");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("POST-QUANTUM TRANSACTION DRY-RUN (NOT BROADCAST)"));
    assert!(stdout.contains("DRY RUN"));
    assert!(stdout.contains("Falcon-512"));
    assert!(stdout.contains("Explicit Carrier (Tx #1 Account Activation)"));
    assert!(stdout.contains("8.0 STELL"));
    assert!(stdout.contains("Envelope Format: PQ1"));
    assert!(stdout.contains("bytes (explicit on-chain registration)"));
    assert!(stdout.contains("Computed TxHash:"));
    assert!(stdout.contains("✅ Valid PQ1 Frame"));
}

#[test]
fn test_cli_pq_transfer_dry_run_hybrid_explicit() {
    let bin = env!("CARGO_BIN_EXE_stell");
    let password = "test_password_12345";
    let wallet_path = create_temp_wallet(bin, password);
    let to_hex = "dd".repeat(32);

    let out = Command::new(bin)
        .args([
            "--wallet",
            wallet_path.to_str().unwrap(),
            "pq-transfer",
            &to_hex,
            "3.75",
            "--scheme",
            "hybrid",
            "--activation",
            "--dry-run",
            "--password",
            password,
        ])
        .output()
        .expect("exec dry run");

    let _ = std::fs::remove_file(&wallet_path);
    assert!(
        !out.status.success(),
        "Hybrid dry run must be refused under FULL-PQ"
    );
}

// =============================================================================
// 9. Pure Post-Quantum Defaults: Wallet Creation, Pay Routing, and PQ Status
// =============================================================================

#[test]
fn test_cli_wallet_creation_default_falcon512_scheme() {
    let bin = env!("CARGO_BIN_EXE_stell");
    let password = "default_falcon_pw_12345";
    let tmp = std::env::temp_dir().join(format!(
        "stell_pq_default_wallet_{}_{}.json",
        std::process::id(),
        rand::random::<u64>()
    ));

    // 1. Run `stell new` without --scheme: must default to falcon512!
    let out = Command::new(bin)
        .args([
            "--wallet",
            tmp.to_str().unwrap(),
            "new",
            "--password",
            password,
        ])
        .output()
        .expect("exec new default");

    assert!(out.status.success(), "Creating default wallet must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Falcon-512"),
        "Stdout must state Falcon-512 scheme"
    );
    assert!(
        stdout.contains("Quantum Resistant:    Yes"),
        "Must report Quantum Resistant: Yes"
    );
    assert!(
        stdout.contains("897 bytes"),
        "Must report Falcon-512 public key size 897 bytes"
    );
    assert!(
        stdout.contains("PQ Public Key:"),
        "Must display public key hex"
    );

    // 2. Verify keystore file on disk
    assert!(tmp.exists(), "Keystore file must exist on disk");
    let keystore = security::HardenedKeystore::load(&tmp).expect("Must load keystore");
    assert_eq!(keystore.scheme, "falcon512");
    assert!(keystore.is_pq());
    assert!(keystore.pq_pubkey_hex.is_some());
    let pk_hex = keystore.pq_pubkey_hex.as_ref().unwrap();
    assert_eq!(pk_hex.len(), FALCON512_PUBKEY_LEN * 2);

    // 3. Verify deterministic derivation from unlocked secret
    let sec = keystore.decrypt(password).expect("Decrypt must succeed");
    let expected_kp = pq::PqKeyPair::from_seed(PqScheme::Falcon512, &sec.bytes);
    let expected_addr = expected_kp.derive_address(&DEFAULT_SALT);
    assert_eq!(hex::encode(expected_addr), keystore.address_hex);
    assert_eq!(hex::encode(expected_kp.public_key()), *pk_hex);

    let _ = std::fs::remove_file(&tmp);

    // 4. FULL-PQ: explicit --scheme ed25519 and --scheme hybrid must be refused.
    for refused in ["ed25519", "hybrid"] {
        let tmp_bad =
            std::env::temp_dir().join(format!("stell_{refused}_{}.json", rand::random::<u64>()));
        let out_bad = Command::new(bin)
            .args([
                "--wallet",
                tmp_bad.to_str().unwrap(),
                "new",
                "--scheme",
                refused,
                "--password",
                password,
            ])
            .output()
            .expect("exec new legacy scheme");
        assert!(
            !out_bad.status.success(),
            "{refused} wallet creation must be refused under FULL-PQ"
        );
        let _ = std::fs::remove_file(&tmp_bad);
    }
}

#[test]
fn test_cli_pay_routing_to_pq_transfer_when_falcon512() {
    let bin = env!("CARGO_BIN_EXE_stell");
    let password = "pay_pq_test_pw_12345";
    // `create_temp_wallet` creates a default wallet, which defaults to Falcon-512!
    let wallet_path = create_temp_wallet(bin, password);
    let to_hex = "ee".repeat(32);

    // 1. Run `stell pay` with default scheme on Falcon-512 wallet in dry-run mode
    let out_default = Command::new(bin)
        .args([
            "--wallet",
            wallet_path.to_str().unwrap(),
            "pay",
            &to_hex,
            "12.34",
            "--password",
            password,
            "--dry-run",
        ])
        .output()
        .expect("exec pay default");

    assert!(out_default.status.success(), "Pay dry-run must succeed");
    let stdout_default = String::from_utf8_lossy(&out_default.stdout);
    assert!(
        stdout_default.contains("POST-QUANTUM TRANSACTION DRY-RUN"),
        "Must route to PQ transfer dry-run"
    );
    assert!(
        stdout_default.contains("Falcon-512"),
        "Must use Falcon-512 scheme"
    );
    assert!(
        stdout_default.contains("PQ1"),
        "Must use PQ1 envelope format"
    );
    assert!(
        stdout_default.contains("12.34 STELL"),
        "Must contain payment amount"
    );
    assert!(
        stdout_default.contains("✅ Valid PQ1 Frame"),
        "Frame must be valid PQ1"
    );
    assert!(
        stdout_default.contains("✅ Signature Verifies"),
        "Signature must verify"
    );

    // 2. Run `stell pay` with explicit `--scheme falcon512`
    let out_explicit = Command::new(bin)
        .args([
            "--wallet",
            wallet_path.to_str().unwrap(),
            "pay",
            &to_hex,
            "7.89",
            "--scheme",
            "falcon512",
            "--password",
            password,
            "--dry-run",
        ])
        .output()
        .expect("exec pay explicit falcon512");

    assert!(out_explicit.status.success());
    let stdout_explicit = String::from_utf8_lossy(&out_explicit.stdout);
    assert!(stdout_explicit.contains("POST-QUANTUM TRANSACTION DRY-RUN"));
    assert!(stdout_explicit.contains("Falcon-512"));
    assert!(stdout_explicit.contains("PQ1"));

    // 3. FULL-PQ: `stell pay` with explicit `--scheme hybrid` must be refused.
    let out_hyb = Command::new(bin)
        .args([
            "--wallet",
            wallet_path.to_str().unwrap(),
            "pay",
            &to_hex,
            "2.50",
            "--scheme",
            "hybrid",
            "--password",
            password,
            "--dry-run",
        ])
        .output()
        .expect("exec pay explicit hybrid");

    assert!(
        !out_hyb.status.success(),
        "hybrid pay must be refused under FULL-PQ"
    );

    let _ = std::fs::remove_file(&wallet_path);
}

#[test]
fn test_cli_pq_status_command() {
    let bin = env!("CARGO_BIN_EXE_stell");
    let password = "status_pw_12345";
    let wallet_path = create_temp_wallet(bin, password);

    // 1. Run `pq-status` with an active wallet
    let out = Command::new(bin)
        .args(["--wallet", wallet_path.to_str().unwrap(), "pq-status"])
        .output()
        .expect("exec pq-status with wallet");

    assert!(out.status.success(), "pq-status command must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("STELLEREUM POST-QUANTUM CRYPTOGRAPHY STATUS"));
    assert!(stdout.contains("Falcon-512"));
    assert!(stdout.contains("ML-DSA-44"));
    assert!(stdout.contains("Hybrid"));
    assert!(stdout.contains("Ed25519"));
    assert!(stdout.contains("PQ-BFT v4"));
    assert!(stdout.contains("Wire Frame"));
    assert!(stdout.contains("PQ1"));
    assert!(stdout.contains("LOCAL WALLET STATUS:"));
    assert!(stdout.contains("Quantum Resistant:    Yes (Pure Post-Quantum)"));

    // 2. Run `pq-status` without specifying a wallet (capabilities and network query)
    let non_existent = std::env::temp_dir().join("non_existent_wallet_404.json");
    let out_no_wallet = Command::new(bin)
        .args(["--wallet", non_existent.to_str().unwrap(), "pq-status"])
        .output()
        .expect("exec pq-status without wallet");

    assert!(out_no_wallet.status.success());
    let stdout_no_wallet = String::from_utf8_lossy(&out_no_wallet.stdout);
    assert!(stdout_no_wallet.contains("STELLEREUM POST-QUANTUM CRYPTOGRAPHY STATUS"));
    assert!(stdout_no_wallet.contains("POST-QUANTUM SCHEME CAPABILITIES:"));
    assert!(stdout_no_wallet.contains("Falcon-512"));
    assert!(stdout_no_wallet.contains("No wallet found"));

    let _ = std::fs::remove_file(&wallet_path);
}
