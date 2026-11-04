//! On-chain contract SOURCE VERIFICATION (audit P2 item 15).
//!
//! The explorer serves decoded events and contract pages, but nothing proves
//! that a deployed WASM blob was compiled from a claimed source. This module
//! is the practical, Sourcify-style answer for a `.wat`-canonical chain:
//!
//! * the canonical source form is the `.wat` TEXT (the repo already ships
//!   `.wat` contracts under `contracts/`, and deploys compile them with the
//!   [`wat`] crate — the same pipeline verification re-runs);
//! * the deterministic build fingerprint is `source_hash = BLAKE3(source_text)`;
//! * verification recompiles the claimed source with the deploy-time pipeline,
//!   hashes the rebuilt bytecode and compares it to the on-chain `code_hash`;
//! * verification is strictly READ-ONLY: it never mutates state. The only
//!   mutation is the optional `source_hash` registration, which is an
//!   explicit, creator-signed action
//!   ([`verify_register_signature`]/`stell_registerContractSource`).
//!
//! # Trust model (what "verified" actually proves)
//!
//! `verified == true` proves exactly this, and nothing more:
//!
//! 1. the bytes the node has on-chain for this contract are byte-identical to
//!    what the CURRENT node build of the [`wat`] compiler produces from the
//!    submitted source text with the claimed flags;
//! 2. `source_hash` is the BLAKE3 digest of exactly that source text.
//!
//! It does NOT prove: that the source is safe to interact with (a verified
//! backdoor is still a backdoor); that the source matches any OTHER compiler
//! version (the claimed `compiler` MUST name this pipeline — anything else is
//! REFUSED, fail-closed); that the contract behaved honestly in the past; or
//! that the on-chain bytecode was built with honest flags (flags outside the
//! allowlist are REFUSED because `wat::parse_str` has no flag surface to
//! reproduce them with).
//!
//! Like Sourcify/NEAR/MultiversX verification, this is a transparency claim,
//! not a safety certificate.

use serde::{Deserialize, Serialize};

/// Maximum accepted source text (1 MiB — same order as [`crate::contract::MAX_CONTRACT_CODE_SIZE`]).
pub const MAX_CONTRACT_SOURCE_SIZE: usize = 1024 * 1024;

/// Compilers this node can reproduce. The node compiles with the [`wat`]
/// crate — the same pipeline used at deploy time — so only claims naming
/// that pipeline are answerable. Anything else is REFUSED (`verified: false`),
/// never guessed.
pub const SUPPORTED_COMPILER_NAMES: &[&str] =
    &["wat-1.0", "wat2wasm-1.0", "wat", "wat2wasm", "wast-1.0"];

/// Compiler flags this node can reproduce. `wat::parse_str` has no flag
/// surface (canonical encoding, always), so only the no-op spellings are
/// accepted; anything else is REFUSED because the node could not have
/// reproduced that build.
pub const SUPPORTED_COMPILER_FLAGS: &[&str] = &["", "default", "canonical", "--canonical"];

/// Domain separation for the source-registration signature (see
/// [`register_message`]).
pub const REGISTER_SOURCE_DOMAIN: &[u8] = b"STELL_REGISTER_SOURCE";

/// Outcome of [`verify_source_for_code_hash`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceVerification {
    pub verified: bool,
    pub onchain_code_hash: String,
    pub rebuilt_code_hash: String,
    pub source_hash: String,
    pub compiler: String,
    pub compiler_flags: String,
    /// Machine-readable refusal reason when `verified == false`
    /// (`"ok"` when verified).
    pub reason: String,
}

impl SourceVerification {
    fn refused(
        onchain: &[u8; 32],
        rebuilt: Option<&[u8; 32]>,
        source_hash: [u8; 32],
        compiler: &str,
        flags: &str,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            verified: false,
            onchain_code_hash: hex::encode(onchain),
            rebuilt_code_hash: rebuilt.map(hex::encode).unwrap_or_default(),
            source_hash: hex::encode(source_hash),
            compiler: compiler.to_string(),
            compiler_flags: flags.to_string(),
            reason: reason.into(),
        }
    }
}

/// `source_hash = BLAKE3(source_text)` — the deterministic build fingerprint.
#[inline]
pub fn source_hash(source_text: &[u8]) -> [u8; 32] {
    *blake3::hash(source_text).as_bytes()
}

/// Compile `.wat` source text with the deploy-time pipeline.
pub fn compile_wat_source(source_text: &str) -> Result<Vec<u8>, String> {
    wat::parse_str(source_text).map_err(|e| format!("source does not compile with wat: {e}"))
}

/// BLAKE3 of bytecode (the deterministic-deploy code-hash algorithm).
#[inline]
pub fn code_hash_blake3(code: &[u8]) -> [u8; 32] {
    *blake3::hash(code).as_bytes()
}

/// SHA-256 of bytecode (the legacy `ContractRegistry::deploy` code-hash algorithm).
#[inline]
pub fn code_hash_sha256(code: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(code).into()
}

/// True when `compiler` names the pipeline this node can reproduce.
pub fn is_supported_compiler(compiler: &str) -> bool {
    let norm = compiler.trim().to_ascii_lowercase();
    SUPPORTED_COMPILER_NAMES.iter().any(|c| *c == norm)
}

/// True when `flags` name a build this node can reproduce.
pub fn is_supported_flags(flags: &str) -> bool {
    let norm = flags.trim().to_ascii_lowercase();
    SUPPORTED_COMPILER_FLAGS.iter().any(|f| *f == norm)
}

/// Decode the source-text bytes from the RPC/indexer parameters.
///
/// * `source` — the `.wat` text inline;
/// * `source_hex` — hex (`0x`-prefixed or bare) of the UTF-8 `.wat` text.
///
/// Returns the raw source bytes (still to be UTF-8-checked by the caller).
pub fn decode_source_bytes(
    source: Option<&str>,
    source_hex: Option<&str>,
) -> Result<Vec<u8>, String> {
    if let Some(hex_text) = source_hex {
        let clean = hex_text
            .trim()
            .strip_prefix("0x")
            .or_else(|| hex_text.trim().strip_prefix("0X"))
            .unwrap_or(hex_text.trim());
        if clean.is_empty() || clean.len() % 2 != 0 {
            return Err("invalid source_hex: expected even-length hex".to_string());
        }
        let bytes = hex::decode(clean).map_err(|e| format!("invalid source_hex: {e}"))?;
        if bytes.is_empty() {
            return Err("empty source".to_string());
        }
        if bytes.len() > MAX_CONTRACT_SOURCE_SIZE {
            return Err(format!(
                "source too large: {} bytes (max {MAX_CONTRACT_SOURCE_SIZE})",
                bytes.len()
            ));
        }
        return Ok(bytes);
    }
    match source {
        Some(text) => {
            if text.is_empty() {
                return Err("empty source".to_string());
            }
            if text.len() > MAX_CONTRACT_SOURCE_SIZE {
                return Err(format!(
                    "source too large: {} bytes (max {MAX_CONTRACT_SOURCE_SIZE})",
                    text.len()
                ));
            }
            Ok(text.as_bytes().to_vec())
        }
        None => Err("missing source: provide 'source' (wat text) or 'source_hex'".to_string()),
    }
}

/// Verify claimed `.wat` source against an on-chain code hash.
///
/// Pure and read-only: compiles `source_text` with the deploy-time pipeline
/// and compares the rebuilt bytecode hash against `onchain_code_hash`. Both
/// historical code-hash algorithms are accepted (BLAKE3 for deterministic
/// deploys, SHA-256 for legacy `deploy`), because the stored hash — not a
/// recomputation — is the ground truth.
pub fn verify_source_for_code_hash(
    onchain_code_hash: &[u8; 32],
    source_text: &[u8],
    compiler: &str,
    compiler_flags: &str,
) -> SourceVerification {
    let shash = source_hash(source_text);
    if !is_supported_compiler(compiler) {
        return SourceVerification::refused(
            onchain_code_hash,
            None,
            shash,
            compiler,
            compiler_flags,
            format!(
                "unsupported compiler '{compiler}': this node reproduces only {SUPPORTED_COMPILER_NAMES:?}"
            ),
        );
    }
    if !is_supported_flags(compiler_flags) {
        return SourceVerification::refused(
            onchain_code_hash,
            None,
            shash,
            compiler,
            compiler_flags,
            format!(
                "unsupported compiler_flags '{compiler_flags}': this node reproduces only {SUPPORTED_COMPILER_FLAGS:?}"
            ),
        );
    }
    let text = match std::str::from_utf8(source_text) {
        Ok(t) => t,
        Err(_) => {
            return SourceVerification::refused(
                onchain_code_hash,
                None,
                shash,
                compiler,
                compiler_flags,
                "source is not valid UTF-8 wat text",
            )
        }
    };
    let rebuilt = match compile_wat_source(text) {
        Ok(b) => b,
        Err(e) => {
            return SourceVerification::refused(
                onchain_code_hash,
                None,
                shash,
                compiler,
                compiler_flags,
                e,
            )
        }
    };
    let rebuilt_blake3 = code_hash_blake3(&rebuilt);
    let rebuilt_sha256 = code_hash_sha256(&rebuilt);
    // The stored hash is ground truth; accept either historical algorithm so
    // contracts from both deploy paths verify.
    let matched = if rebuilt_blake3 == *onchain_code_hash {
        Some(rebuilt_blake3)
    } else if rebuilt_sha256 == *onchain_code_hash {
        Some(rebuilt_sha256)
    } else {
        None
    };
    match matched {
        Some(m) => SourceVerification {
            verified: true,
            onchain_code_hash: hex::encode(onchain_code_hash),
            rebuilt_code_hash: hex::encode(m),
            source_hash: hex::encode(shash),
            compiler: compiler.to_string(),
            compiler_flags: compiler_flags.to_string(),
            reason: "ok".to_string(),
        },
        None => SourceVerification::refused(
            onchain_code_hash,
            Some(&rebuilt_blake3),
            shash,
            compiler,
            compiler_flags,
            "rebuilt bytecode hash does not match the on-chain code hash",
        ),
    }
}

/// The bytes the contract creator signs to register a source hash:
/// `b"STELL_REGISTER_SOURCE" || contract || source_hash`.
pub fn register_message(contract: &[u8; 32], source_hash: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(REGISTER_SOURCE_DOMAIN.len() + 64);
    m.extend_from_slice(REGISTER_SOURCE_DOMAIN);
    m.extend_from_slice(contract);
    m.extend_from_slice(source_hash);
    m
}

/// Verify the creator's ed25519 signature authorising a `source_hash`
/// registration. The creator address IS the ed25519 pubkey (chain address
/// convention), so no key lookup is needed — but the signature MUST verify,
/// otherwise anyone could pin a false "verified" label on someone else's
/// contract.
pub fn verify_register_signature(
    creator: &[u8; 32],
    contract: &[u8; 32],
    source_hash: &[u8; 32],
    signature_hex: &str,
) -> Result<(), String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let clean = signature_hex
        .trim()
        .strip_prefix("0x")
        .or_else(|| signature_hex.trim().strip_prefix("0X"))
        .unwrap_or(signature_hex.trim());
    let bytes = hex::decode(clean).map_err(|e| format!("invalid signature hex: {e}"))?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| "invalid signature: expected 64 bytes".to_string())?;
    let key = VerifyingKey::from_bytes(creator).map_err(|e| format!("invalid creator key: {e}"))?;
    key.verify(
        &register_message(contract, source_hash),
        &Signature::from_bytes(&arr),
    )
    .map_err(|_| "signature does not verify against the contract creator".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::ContractRegistry;

    const KNOWN_WAT: &str = r#"(module
      (import "host" "sload" (func $sload (param i64) (result i64)))
      (import "host" "sstore" (func $sstore (param i64 i64)))
      (import "host" "emit" (func $emit (param i64 i64)))
      (func (export "get") (param i64) (result i64) (call $sload (i64.const 0)))
      (func (export "set") (param i64) (result i64)
        (call $sstore (i64.const 0) (local.get 0)) (local.get 0))
    )"#;

    fn deploy_known() -> (ContractRegistry, [u8; 32]) {
        let wasm = compile_wat_source(KNOWN_WAT).expect("known wat compiles");
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([7u8; 32], wasm, 1).expect("deploy");
        (reg, addr)
    }

    #[test]
    fn known_wat_source_verifies() {
        let (reg, addr) = deploy_known();
        let c = reg.get(&addr).expect("contract");
        let v = verify_source_for_code_hash(
            &c.code_hash,
            KNOWN_WAT.as_bytes(),
            "wat2wasm-1.0",
            "default",
        );
        assert!(v.verified, "known source must verify: {}", v.reason);
        assert_eq!(
            v.source_hash,
            hex::encode(source_hash(KNOWN_WAT.as_bytes()))
        );
        assert_eq!(v.onchain_code_hash, hex::encode(c.code_hash));
        assert_eq!(v.reason, "ok");
    }

    #[test]
    fn tampered_source_is_refused() {
        let (reg, addr) = deploy_known();
        let c = reg.get(&addr).expect("contract");
        let tampered = KNOWN_WAT.replace("i64.const 0", "i64.const 1");
        assert_ne!(tampered, KNOWN_WAT);
        let v = verify_source_for_code_hash(&c.code_hash, tampered.as_bytes(), "wat2wasm-1.0", "");
        assert!(!v.verified, "tampered source must NOT verify");
        assert!(v.reason.contains("does not match"));
    }

    #[test]
    fn wrong_compiler_claim_is_refused() {
        let (reg, addr) = deploy_known();
        let c = reg.get(&addr).expect("contract");
        for compiler in ["solc-0.8.24", "rustc-1.75", "tinygo-0.30", ""] {
            let v = verify_source_for_code_hash(&c.code_hash, KNOWN_WAT.as_bytes(), compiler, "");
            assert!(!v.verified, "compiler '{compiler}' must be refused");
            assert!(v.reason.contains("unsupported compiler"), "{}", v.reason);
        }
    }

    #[test]
    fn unknown_flags_are_refused() {
        let (reg, addr) = deploy_known();
        let c = reg.get(&addr).expect("contract");
        let v = verify_source_for_code_hash(
            &c.code_hash,
            KNOWN_WAT.as_bytes(),
            "wat2wasm-1.0",
            "-O3 --fake-flag",
        );
        assert!(!v.verified);
        assert!(
            v.reason.contains("unsupported compiler_flags"),
            "{}",
            v.reason
        );
    }

    #[test]
    fn garbage_source_is_refused_not_accepted() {
        let (reg, addr) = deploy_known();
        let c = reg.get(&addr).expect("contract");
        let v = verify_source_for_code_hash(
            &c.code_hash,
            b"(module this is not valid wat ((( ",
            "wat",
            "",
        );
        assert!(!v.verified);
        assert!(v.reason.contains("does not compile"), "{}", v.reason);
    }

    #[test]
    fn source_hash_is_deterministic_fingerprint() {
        assert_eq!(source_hash(b"a"), source_hash(b"a"));
        assert_ne!(source_hash(b"a"), source_hash(b"b"));
        assert_eq!(source_hash(b"a").len(), 32);
    }

    #[test]
    fn register_signature_round_trip() {
        use ed25519_dalek::Signer;
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let creator = sk.verifying_key().to_bytes();
        let contract = [1u8; 32];
        let shash = source_hash(b"src");
        let sig = sk.sign(&register_message(&contract, &shash));
        verify_register_signature(&creator, &contract, &shash, &hex::encode(sig.to_bytes()))
            .expect("valid registration signature verifies");
        // Wrong contract: the same signature must NOT verify.
        assert!(verify_register_signature(
            &creator,
            &[2u8; 32],
            &shash,
            &hex::encode(sig.to_bytes())
        )
        .is_err());
    }
}
